use super::*;
use std::collections::BTreeMap;

fn sample_lockfile() -> Lockfile {
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "@lpm.dev/neo.highlight".to_string(),
        version: "1.1.1".to_string(),
        source: Some("registry+https://lpm.dev".to_string()),
        integrity: Some("sha512-abc123...".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec!["react@999.999.999".to_string()],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "react".to_string(),
        version: "999.999.999".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf
}

#[test]
fn serialize_roundtrip() {
    let lf = sample_lockfile();
    let toml_str = lf.to_toml().unwrap();
    let parsed = Lockfile::from_toml(&toml_str).unwrap();
    assert_eq!(lf, parsed);
}

fn lockfile_with_verified_provenance() -> (Lockfile, PackageKey, LockedProvenance) {
    let mut lockfile = Lockfile::new();
    let package = LockedPackage {
        name: "axios".to_string(),
        version: "1.14.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some(
            "sha512-3Y8yrqLSwjuzpXuZ0oIYZ/XGgLwUIBU3uLvbcpb0pidD9ctpShJd43KSlEEkVQg6DS0G9NKyzOvBfUtDKEyHvQ=="
                .to_string(),
        ),
        ..LockedPackage::default()
    };
    let key = package.package_key();
    lockfile.add_package(package);
    let evidence = LockedProvenance {
        snapshot: lpm_common::ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".to_string()),
            workflow_path: Some(".github/workflows/publish.yml".to_string()),
            workflow_ref: Some("refs/tags/v1.14.0".to_string()),
            attestation_cert_sha256: Some("sha256-leaf".to_string()),
        },
        subject_name: "pkg:npm/axios@1.14.0".to_string(),
        subject_sha512: "dd8f32aea2d2c23bb3a57b99d2821867f5c680bc14201537b8bbdb7296f4a62743f5cb694a125de3729294412455083a0d2d06f4d2b2ccebc17d4b43284c87bd".to_string(),
        integrated_time_secs: 1_700_000_000,
        log_id: "rekor-log".to_string(),
        log_index: 42,
        bundle_sha256: format!("sha256-{}", "ab".repeat(32)),
    };
    lockfile.set_verified_provenance(&key, evidence.clone());
    (lockfile, key, evidence)
}

#[test]
fn verified_provenance_round_trips_through_toml_and_binary() {
    let (lockfile, key, evidence) = lockfile_with_verified_provenance();

    let toml = lockfile.to_toml().expect("serialize provenance evidence");
    let from_toml = Lockfile::from_toml(&toml).expect("parse provenance evidence");
    assert_eq!(from_toml.verified_provenance(&key), Some(&evidence));

    let binary = binary::to_binary(&lockfile).expect("serialize binary provenance evidence");
    let dir = tempfile::tempdir().unwrap();
    let binary_path = dir.path().join(binary::BINARY_LOCKFILE_NAME);
    std::fs::write(&binary_path, binary).unwrap();
    let reader = BinaryLockfileReader::open(&binary_path)
        .unwrap()
        .expect("open binary lockfile");
    let from_binary = reader
        .to_lockfile()
        .expect("parse binary provenance evidence");
    assert_eq!(from_binary.verified_provenance(&key), Some(&evidence));
}

#[test]
fn from_toml_rejects_orphan_provenance_entry() {
    let (lockfile, key, _) = lockfile_with_verified_provenance();
    let toml = lockfile
        .to_toml()
        .expect("serialize valid provenance evidence")
        .replace(&key.lockfile_id(), "orphan@9.9.9#r-deadbeefdeadbeef");

    let error = Lockfile::from_toml(&toml).expect_err("orphan evidence must be rejected");
    assert!(
        error
            .to_string()
            .contains("does not match any locked package"),
        "unexpected error: {error}"
    );
}

#[test]
fn from_toml_rejects_empty_required_provenance_field() {
    let (lockfile, _, _) = lockfile_with_verified_provenance();
    let toml = lockfile
        .to_toml()
        .expect("serialize valid provenance evidence")
        .replace(
            "subject-name = \"pkg:npm/axios@1.14.0\"",
            "subject-name = \"\"",
        );

    let error = Lockfile::from_toml(&toml).expect_err("empty subject must be rejected");
    assert!(
        error.to_string().contains("empty required subject-name"),
        "unexpected error: {error}"
    );
}

#[test]
fn from_toml_rejects_negative_provenance_log_index() {
    let (lockfile, _, _) = lockfile_with_verified_provenance();
    let toml = lockfile
        .to_toml()
        .expect("serialize valid provenance evidence")
        .replace("log-index = 42", "log-index = -1");

    let error = Lockfile::from_toml(&toml).expect_err("negative log index must be rejected");
    assert!(
        error.to_string().contains("invalid log-index"),
        "unexpected error: {error}"
    );
}

#[test]
fn from_toml_rejects_provenance_bound_to_wrong_tarball_digest() {
    let (lockfile, _, _) = lockfile_with_verified_provenance();
    let toml = lockfile
        .to_toml()
        .expect("serialize valid provenance evidence")
        .replace(
            "dd8f32aea2d2c23bb3a57b99d2821867f5c680bc14201537b8bbdb7296f4a62743f5cb694a125de3729294412455083a0d2d06f4d2b2ccebc17d4b43284c87bd",
            &"00".repeat(64),
        );

    let error = Lockfile::from_toml(&toml).expect_err("mismatched digest must be rejected");
    assert!(
        error
            .to_string()
            .contains("subject-sha512 does not match the locked package integrity"),
        "unexpected error: {error}"
    );
}

#[test]
fn dependency_node_engine_round_trips_through_toml() {
    let mut lf = sample_lockfile();
    lf.packages[0].node_engine = Some(">=22 <23".to_string());

    let toml = lf.to_toml().expect("serialize dependency Node engine");
    let parsed = Lockfile::from_toml(&toml).expect("parse dependency Node engine");

    assert_eq!(parsed.packages[0].node_engine.as_deref(), Some(">=22 <23"));
}

#[test]
fn dependency_node_engine_metadata_requires_toml_fallback() {
    let mut lf = sample_lockfile();
    lf.packages[0].node_engine = Some(">=22".to_string());

    assert!(!binary::binary_format_supports(&lf));
}

#[test]
fn toml_output_is_readable() {
    let lf = sample_lockfile();
    let toml_str = lf.to_toml().unwrap();

    assert!(toml_str.contains("[metadata]"));
    // Assert against the constant so a future version bump only
    // requires one change.
    assert!(toml_str.contains(&format!("lockfile-version = {}", LOCKFILE_VERSION)));
    assert!(toml_str.contains("[[packages]]"));
    assert!(toml_str.contains("@lpm.dev/neo.highlight"));
    assert!(toml_str.contains("react"));
}

#[test]
fn importer_snapshots_round_trip_dependency_sections() {
    let mut lf = Lockfile::new();
    let importer = ImporterSnapshot {
        dependencies: BTreeMap::from([("react".to_string(), "^19.0.0".to_string())]),
        dev_dependencies: BTreeMap::from([("vitest".to_string(), "^4.0.0".to_string())]),
        optional_dependencies: BTreeMap::from([("fsevents".to_string(), "^2.3.3".to_string())]),
        peer_dependencies: BTreeMap::from([("typescript".to_string(), ">=5".to_string())]),
        workspace_root_peer_providers_fingerprint: Some("sha256-workspace-root".to_string()),
        ..ImporterSnapshot::default()
    };
    lf.importers.insert(".".to_string(), importer.clone());

    let toml = lf.to_toml().expect("serialize importer snapshot");
    assert!(
        toml.contains("[importers.\".\".dependencies]")
            && toml.contains("[importers.\".\".dev-dependencies]")
            && toml.contains("[importers.\".\".optional-dependencies]")
            && toml.contains("[importers.\".\".peer-dependencies]")
            && toml.contains("workspace-root-peer-providers-fingerprint"),
        "lockfile must serialize importer dependency sections, got:\n{toml}"
    );

    let parsed = Lockfile::from_toml(&toml).expect("parse importer snapshot");
    assert_eq!(parsed.importers.get(".").unwrap(), &importer);
}

#[test]
fn patch_records_round_trip_and_skip_binary() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = toml_path.with_extension("lockb");

    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-original".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&toml_path).unwrap();
    assert!(
        binary_path.exists(),
        "binary-compatible lockfile must write lpm.lockb before patch metadata is present"
    );

    lf.patches.insert(
        "lodash@4.17.21".to_string(),
        LockfilePatch {
            path: "patches/lodash@4.17.21.patch".to_string(),
            sha256: "sha256-0123456789abcdef".to_string(),
            original_integrity: "sha512-original".to_string(),
        },
    );
    let toml = lf.to_toml().expect("serialize patch records");
    assert!(
        toml.contains("[patches.\"lodash@4.17.21\"]")
            && toml.contains("path = \"patches/lodash@4.17.21.patch\"")
            && toml.contains("sha256 = \"sha256-0123456789abcdef\"")
            && toml.contains("original-integrity = \"sha512-original\""),
        "lockfile must serialize patch evidence, got:\n{toml}"
    );
    let parsed = Lockfile::from_toml(&toml).expect("parse patch records");
    assert_eq!(parsed.patches, lf.patches);

    lf.write_all(&toml_path).unwrap();
    assert!(
        !binary_path.exists(),
        "patch-bearing lockfile must remove stale lpm.lockb"
    );
}

#[test]
fn write_all_skips_binary_when_importer_snapshots_present() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = toml_path.with_extension("lockb");

    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&toml_path).unwrap();
    assert!(
        binary_path.exists(),
        "binary-compatible lockfile must write lpm.lockb"
    );

    lf.importers.insert(
        ".".to_string(),
        ImporterSnapshot {
            dependencies: BTreeMap::from([("foo".to_string(), "^1.0.0".to_string())]),
            ..ImporterSnapshot::default()
        },
    );
    lf.write_all(&toml_path).unwrap();
    assert!(
        !binary_path.exists(),
        "importer-bearing lockfile must remove stale lpm.lockb"
    );
}

/// Every default `lpm install` writes a lockfile produced by
/// greedy-fusion — the field was previously hardcoded to "pubgrub".
/// The constructor must round-trip the resolver name
/// the dispatch site picked, AND the bare `Lockfile::new()` default
/// must agree with the install default so test/library callers
/// don't quietly retag a fresh lockfile as pubgrub.
#[test]
fn new_with_resolver_records_resolver_name() {
    for name in ["greedy-fusion", "greedy", "pubgrub"] {
        let lf = Lockfile::new_with_resolver(name);
        assert_eq!(
            lf.metadata.resolved_with.as_deref(),
            Some(name),
            "Lockfile::new_with_resolver must round-trip the resolver name verbatim",
        );
    }

    let default = Lockfile::new();
    assert_eq!(
        default.metadata.resolved_with.as_deref(),
        Some(DEFAULT_RESOLVED_WITH),
    );
    assert_eq!(DEFAULT_RESOLVED_WITH, "greedy-fusion");
}

#[test]
fn auto_isolated_peer_conflicts_metadata_round_trips_when_true() {
    let mut lf = Lockfile::new();
    lf.metadata.auto_isolated_peer_conflicts = true;

    let toml = lf.to_toml().unwrap();
    assert!(
        toml.contains("auto-isolated-peer-conflicts = true"),
        "true auto-isolated metadata must serialize: {toml}"
    );

    let parsed = Lockfile::from_toml(&toml).unwrap();
    assert!(parsed.metadata.auto_isolated_peer_conflicts);
}

#[test]
fn auto_isolated_peer_conflicts_metadata_defaults_false_and_is_skipped() {
    let lf = Lockfile::new();

    let toml = lf.to_toml().unwrap();
    assert!(
        !toml.contains("auto-isolated-peer-conflicts"),
        "false auto-isolated metadata must stay out of ordinary lockfiles: {toml}"
    );

    let parsed = Lockfile::from_toml(
        r#"
[metadata]
lockfile-version = 2
resolved-with = "greedy-fusion"
"#,
    )
    .unwrap();
    assert!(!parsed.metadata.auto_isolated_peer_conflicts);
}

#[test]
fn catalog_snapshots_roundtrip_when_present() {
    let mut lf = Lockfile::new();
    lf.catalogs.insert(
        "default".to_string(),
        BTreeMap::from([(
            "react".to_string(),
            CatalogSnapshotEntry {
                specifier: "^18.2.0".to_string(),
                version: "18.3.1".to_string(),
                reference: "catalog:".to_string(),
            },
        )]),
    );

    let toml = lf.to_toml().unwrap();
    assert!(
        toml.contains("[catalogs.default.react]"),
        "catalog snapshot must serialize as a top-level catalogs table: {toml}"
    );

    let parsed = Lockfile::from_toml(&toml).unwrap();
    assert_eq!(parsed.catalogs, lf.catalogs);
}

#[test]
fn catalog_snapshots_are_additive_and_skipped_when_empty() {
    let lf = Lockfile::new();

    let toml = lf.to_toml().unwrap();
    assert!(
        !toml.contains("[catalogs"),
        "ordinary lockfiles should not serialize an empty catalog snapshot: {toml}"
    );

    let parsed = Lockfile::from_toml(
        r#"
[metadata]
lockfile-version = 2
resolved-with = "greedy-fusion"
"#,
    )
    .unwrap();
    assert!(parsed.catalogs.is_empty());
}

#[test]
fn binary_format_does_not_claim_support_for_catalog_snapshots() {
    let mut lf = Lockfile::new();
    lf.catalogs.insert(
        "default".to_string(),
        BTreeMap::from([(
            "react".to_string(),
            CatalogSnapshotEntry {
                specifier: "^18.2.0".to_string(),
                version: "18.3.1".to_string(),
                reference: "catalog:".to_string(),
            },
        )]),
    );

    assert!(
        !binary::binary_format_supports(&lf),
        "binary lockfile format must be skipped when TOML-only catalog snapshots are present"
    );
}

#[test]
fn packages_sorted_by_name() {
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "zlib".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "alpha".to_string(),
        version: "2.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });

    assert_eq!(lf.packages[0].name, "alpha");
    assert_eq!(lf.packages[1].name, "zlib");
}

#[test]
fn find_package_by_name() {
    let lf = sample_lockfile();
    let pkg = lf.find_package("react").unwrap();
    assert_eq!(pkg.version, "999.999.999");
    assert!(lf.find_package("nonexistent").is_none());
}

#[test]
fn tarball_roundtrips_when_present() {
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-xyz".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
    });

    let toml_str = lf.to_toml().unwrap();
    // Serialized form must include the new field when populated.
    assert!(
        toml_str.contains("tarball = \"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\""),
        "expected tarball field in serialized TOML, got:\n{toml_str}"
    );

    let parsed = Lockfile::from_toml(&toml_str).unwrap();
    assert_eq!(lf, parsed);
    assert_eq!(
        parsed.packages[0].tarball.as_deref(),
        Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
    );
}

#[test]
fn tarball_absent_keeps_old_lockfiles_byte_identical() {
    // `#[serde(skip_serializing_if = "Option::is_none")]` must
    // keep lockfiles byte-stable when no package has a tarball
    // URL — existing projects must be unaffected until they
    // re-run `lpm install`.
    let lf = sample_lockfile();
    let toml_str = lf.to_toml().unwrap();
    assert!(
        !toml_str.contains("tarball"),
        "lockfile with no tarball URLs must not emit a `tarball` field, got:\n{toml_str}"
    );

    let parsed = Lockfile::from_toml(&toml_str).unwrap();
    assert_eq!(lf, parsed);
    for pkg in &parsed.packages {
        assert_eq!(pkg.tarball, None);
    }
}

#[test]
fn tarball_mixed_population_roundtrips() {
    // Real-world rollout window: some entries have a tarball URL,
    // others don't. Per-package `None` must be preserved; `Some`
    // must round-trip with its value.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "express".to_string(),
        version: "4.22.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None, // old entry, not yet re-resolved
    });
    lf.add_package(LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
    });

    let toml_str = lf.to_toml().unwrap();
    let parsed = Lockfile::from_toml(&toml_str).unwrap();
    assert_eq!(lf, parsed);

    let express = parsed.find_package("express").unwrap();
    assert_eq!(express.tarball, None);
    let lodash = parsed.find_package("lodash").unwrap();
    assert_eq!(
        lodash.tarball.as_deref(),
        Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
    );
}

#[test]
fn registry_signature_metadata_roundtrips_as_human_readable_toml() {
    let toml = r#"
[metadata]
lockfile-version = 3
resolved-with = "greedy-fusion"

[[packages]]
name = "signed-pkg"
version = "1.0.0"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-signed"
registry-published-at = "2025-01-01T00:00:00.000Z"
dependencies = []

[[packages.registry-signatures]]
keyid = "SHA256:abc123"
sig = "MEUCIQDregistrySignature"
"#;

    let lf = Lockfile::from_toml(toml).unwrap();
    let package = &lf.packages[0];
    assert_eq!(
        package.registry_published_at.as_deref(),
        Some("2025-01-01T00:00:00.000Z")
    );
    assert_eq!(package.registry_signatures.len(), 1);
    assert_eq!(
        package.registry_signatures[0].keyid.as_deref(),
        Some("SHA256:abc123")
    );
    assert_eq!(
        package.registry_signatures[0].sig.as_deref(),
        Some("MEUCIQDregistrySignature")
    );

    let serialized = lf.to_toml().unwrap();

    assert!(
        serialized.contains("registry-published-at = \"2025-01-01T00:00:00.000Z\""),
        "registry publish timestamp must survive a lockfile roundtrip:\n{serialized}"
    );
    assert!(
        serialized.contains("[[packages.registry-signatures]]"),
        "registry signatures must remain nested under the package entry:\n{serialized}"
    );
    assert!(
        serialized.contains("keyid = \"SHA256:abc123\"")
            && serialized.contains("sig = \"MEUCIQDregistrySignature\""),
        "registry signature key id and payload must survive a lockfile roundtrip:\n{serialized}"
    );
}

#[test]
fn from_toml_rejects_empty_optional_strings() {
    // The binary writer rejects empty optional strings at
    // serialization time; `from_toml` must also reject at parse
    // time to avoid asymmetric late failure. Reject at the parse
    // boundary for all three fields.
    for (field, snippet) in [
        ("tarball", "tarball = \"\""),
        ("source", "source = \"\""),
        ("integrity", "integrity = \"\""),
    ] {
        let toml_str = format!(
            r#"
[metadata]
lockfile-version = 1

[[packages]]
name = "bad-pkg"
version = "1.0.0"
{snippet}
"#
        );
        let err = Lockfile::from_toml(&toml_str).expect_err(&format!(
            "empty {field} must be rejected at TOML parse time"
        ));
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("empty '{field}'")) && msg.contains("bad-pkg"),
            "error for {field} should name field and package, got: {msg}"
        );
    }
}

#[test]
fn old_lockfile_without_tarball_field_parses() {
    // Forward-compat: old lockfiles without a tarball field must
    // parse cleanly (tarball = None).
    let toml_str = r#"
[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

[[packages]]
name = "react"
version = "18.2.0"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-old"
dependencies = []
"#;
    let parsed = Lockfile::from_toml(toml_str).unwrap();
    assert_eq!(parsed.packages.len(), 1);
    assert_eq!(parsed.packages[0].tarball, None);
}

#[test]
fn reject_future_lockfile_version() {
    let toml_str = r#"
[metadata]
lockfile-version = 999

[[packages]]
name = "foo"
version = "1.0.0"
"#;
    let result = Lockfile::from_toml(toml_str);
    assert!(result.is_err());
}

#[test]
fn write_and_read_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.lock");

    let lf = sample_lockfile();
    lf.write_to_file(&path).unwrap();

    assert!(path.exists());

    let read_back = Lockfile::read_from_file(&path).unwrap();
    assert_eq!(lf, read_back);
}

#[test]
fn write_to_file_leaves_no_temporary_file_after_success() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.lock");

    let lf = sample_lockfile();
    lf.write_to_file(&path).unwrap();

    assert!(path.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".lpm-")
    }));
}

#[cfg(unix)]
#[test]
fn write_to_file_does_not_follow_preplanted_temp_symlink() {
    use std::os::unix::fs::symlink;

    let project = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let path = project.path().join("lpm.lock");
    let tmp_path = path.with_extension("lock.tmp");
    let sentinel = external.path().join("sentinel");
    let original = b"external sentinel";
    std::fs::write(&sentinel, original).unwrap();
    symlink(&sentinel, &tmp_path).unwrap();

    sample_lockfile().write_to_file(&path).unwrap();

    assert_eq!(std::fs::read(&sentinel).unwrap(), original);
}

#[test]
fn write_to_file_cleans_temporary_file_when_replacement_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.lock");
    let lf = sample_lockfile();

    std::fs::create_dir(&path).unwrap();

    let result = lf.write_to_file(&path);

    assert!(result.is_err(), "replacement of a directory should fail");
    assert!(
        std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".lpm-")),
        "failed write should clean its temporary file"
    );
}

#[test]
fn ensure_gitattributes_creates_file() {
    let dir = tempfile::tempdir().unwrap();
    let ga = dir.path().join(".gitattributes");

    ensure_gitattributes(dir.path()).unwrap();

    assert!(ga.exists());
    let content = std::fs::read_to_string(&ga).unwrap();
    assert!(content.contains("lpm.lockb binary"));
    assert!(content.contains("# lpm"));
}

#[test]
fn ensure_gitattributes_appends_to_existing() {
    let dir = tempfile::tempdir().unwrap();
    let ga = dir.path().join(".gitattributes");

    std::fs::write(&ga, "*.png binary\n").unwrap();
    ensure_gitattributes(dir.path()).unwrap();

    let content = std::fs::read_to_string(&ga).unwrap();
    assert!(content.starts_with("*.png binary\n"));
    assert!(content.contains("lpm.lockb binary"));
}

#[test]
fn ensure_gitattributes_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let ga = dir.path().join(".gitattributes");

    ensure_gitattributes(dir.path()).unwrap();
    let content_first = std::fs::read_to_string(&ga).unwrap();

    ensure_gitattributes(dir.path()).unwrap();
    let content_second = std::fs::read_to_string(&ga).unwrap();

    assert_eq!(content_first, content_second);
}

#[test]
fn ensure_gitattributes_preserves_existing_content() {
    let dir = tempfile::tempdir().unwrap();
    let ga = dir.path().join(".gitattributes");

    let existing = "# Git attributes\n*.jpg binary\n*.pdf binary\n";
    std::fs::write(&ga, existing).unwrap();

    ensure_gitattributes(dir.path()).unwrap();

    let content = std::fs::read_to_string(&ga).unwrap();
    assert!(content.starts_with(existing));
    assert!(content.contains("lpm.lockb binary"));
    assert!(content.contains("*.jpg binary"));
    assert!(content.contains("*.pdf binary"));
}

#[test]
fn safe_source_https_lpm() {
    assert!(is_safe_source("registry+https://lpm.dev"));
}

#[test]
fn safe_source_https_npm() {
    assert!(is_safe_source("registry+https://registry.npmjs.org"));
}

#[test]
fn safe_source_https_custom_registry() {
    assert!(is_safe_source("registry+https://custom-registry.corp.com"));
}

#[test]
fn unsafe_source_http() {
    assert!(!is_safe_source("registry+http://evil.com"));
}

#[test]
fn safe_source_localhost() {
    assert!(is_safe_source("registry+http://localhost:3000"));
}

#[test]
fn safe_source_loopback() {
    assert!(is_safe_source("registry+http://127.0.0.1:3000"));
}

#[test]
fn unsafe_source_ftp() {
    assert!(!is_safe_source("ftp://evil.com/packages"));
}

#[test]
fn unsafe_source_file() {
    assert!(!is_safe_source("file:///etc/passwd"));
}

#[test]
fn safe_source_accepts_commit_pinned_public_github_repository() {
    assert!(is_safe_source(
        "git+https://github.com/rhashimoto/wa-sqlite.git#779219540f66cecaa159da32b3b8936697ba10a7"
    ));
}

#[test]
fn safe_source_rejects_github_repository_without_commit() {
    assert!(!is_safe_source(
        "git+https://github.com/rhashimoto/wa-sqlite.git"
    ));
}

#[test]
fn safe_source_rejects_github_repository_with_credentials() {
    assert!(!is_safe_source(
        "git+https://user:secret@github.com/rhashimoto/wa-sqlite.git#779219540f66cecaa159da32b3b8936697ba10a7"
    ));
}

#[test]
fn to_toml_rejects_git_source_without_archive_integrity() {
    let mut lockfile = Lockfile::new();
    lockfile.add_package(LockedPackage {
        name: "wa-sqlite".to_string(),
        version: "1.0.9".to_string(),
        source: Some(
            "git+https://github.com/rhashimoto/wa-sqlite.git#779219540f66cecaa159da32b3b8936697ba10a7"
                .to_string(),
        ),
        ..Default::default()
    });

    let error = lockfile
        .to_toml()
        .expect_err("Git source without integrity must not serialize");
    assert!(error.to_string().contains("missing archive integrity"));
}

#[test]
fn from_toml_rejects_git_source_with_symbolic_ref() {
    let toml = r#"
[metadata]
lockfile-version = 9

[[packages]]
name = "wa-sqlite"
version = "1.0.9"
source = "git+https://github.com/rhashimoto/wa-sqlite.git#main"
integrity = "sha512-YQ=="
"#;

    let error =
        Lockfile::from_toml(toml).expect_err("Git lockfile source must contain an exact commit");
    assert!(error.to_string().contains("pinned public GitHub"));
}

#[test]
fn from_toml_rejects_git_source_before_git_schema_version() {
    let toml = r#"
[metadata]
lockfile-version = 8

[[packages]]
name = "wa-sqlite"
version = "1.0.9"
source = "git+https://github.com/rhashimoto/wa-sqlite.git#779219540f66cecaa159da32b3b8936697ba10a7"
integrity = "sha512-YQ=="
"#;

    let error = Lockfile::from_toml(toml)
        .expect_err("Git lockfile source must require the Git-aware schema version");
    assert!(error.to_string().contains("lockfile version 9"));
}

#[test]
fn package_key_distinguishes_two_commits_of_same_github_package() {
    let package_at = |commit: &str| LockedPackage {
        name: "example".to_string(),
        version: "1.0.0".to_string(),
        source: Some(format!("git+https://github.com/owner/example.git#{commit}")),
        integrity: Some("sha512-YQ==".to_string()),
        ..Default::default()
    };

    let first = package_at("1111111111111111111111111111111111111111").package_key();
    let second = package_at("2222222222222222222222222222222222222222").package_key();
    assert_ne!(first, second);
}

/// npm-alias metadata round-trips through the TOML serializer.
/// Both `root-aliases` (top-level) and per-package
/// `alias-dependencies` must survive `to_toml` → `from_toml` with
/// byte-identical shape, so warm installs reconstruct the original
/// `node_modules/<local>/` layout.
#[test]
fn toml_roundtrips_npm_alias_metadata() {
    let mut lf = Lockfile::new();
    lf.root_aliases
        .insert("strip-ansi-cjs".to_string(), "strip-ansi".to_string());
    lf.add_package(LockedPackage {
        name: "strip-ansi".to_string(),
        version: "6.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-abc".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec!["ansi-regex@5.0.1".to_string()],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "parent-with-alias-dep".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec!["strip-ansi-cjs@6.0.1".to_string()],
        alias_dependencies: vec![["strip-ansi-cjs".to_string(), "strip-ansi".to_string()]],
        peers: vec![],
        tarball: None,
    });

    let toml = lf.to_toml().expect("TOML serialize must succeed");
    assert!(
        toml.contains("[root-aliases]"),
        "root-aliases must surface as a top-level TOML table"
    );
    assert!(
        toml.contains("alias-dependencies"),
        "per-package alias-dependencies must appear for packages with aliased deps"
    );

    let parsed = Lockfile::from_toml(&toml).expect("TOML parse must succeed");
    assert_eq!(
        parsed, lf,
        "round-trip must preserve every alias field byte-for-byte"
    );
}

#[test]
fn toml_roundtrips_exact_root_resolutions() {
    let mut lockfile = Lockfile::new();
    lockfile.root_resolutions.insert(
        "peer-host".to_string(),
        LockedRootResolution {
            package: "peer-host".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
        },
    );

    let toml = lockfile.to_toml().expect("serialize exact root selection");
    let parsed = Lockfile::from_toml(&toml).expect("parse exact root selection");

    assert_eq!(parsed.root_resolutions, lockfile.root_resolutions);
}

/// The binary format cannot express alias metadata;
/// `binary::to_binary` rejects such lockfiles so callers fall
/// back to TOML-only. `write_all` goes further and proactively
/// removes any stale binary file from a prior non-aliased install.
#[test]
fn write_all_skips_binary_when_root_aliases_present() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = toml_path.with_extension("lockb");

    // First write — non-aliased lockfile produces BOTH files.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&toml_path).unwrap();
    assert!(
        binary_path.exists(),
        "non-aliased lockfile must write binary"
    );

    // Second write — alias-bearing lockfile skips binary and
    // removes any stale file.
    lf.root_aliases
        .insert("alias".to_string(), "foo".to_string());
    lf.write_all(&toml_path).unwrap();
    assert!(
        !binary_path.exists(),
        "alias-bearing lockfile must not leave a stale binary behind"
    );
}

#[test]
fn write_all_skips_binary_when_auto_isolated_peer_conflicts_present() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = toml_path.with_extension("lockb");

    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&toml_path).unwrap();
    assert!(binary_path.exists(), "plain lockfile must write binary");

    lf.metadata.auto_isolated_peer_conflicts = true;
    lf.write_all(&toml_path).unwrap();
    assert!(
        !binary_path.exists(),
        "auto-isolated peer-conflict metadata must not leave a stale binary behind"
    );
}

#[test]
fn empty_deps_not_serialized() {
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    let toml_str = lf.to_toml().unwrap();
    // "dependencies" key should not appear when empty
    assert!(!toml_str.contains("dependencies"));
}

#[test]
fn read_fast_reads_toml_when_binary_is_newer() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = dir.path().join("lpm.lockb");

    let lf = sample_lockfile();
    lf.write_to_file(&toml_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    binary::write_binary(&lf, &binary_path).unwrap();

    let result = Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(result, lf);
}

#[test]
fn read_fast_ignores_newer_binary_that_disagrees_with_toml() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = dir.path().join("lpm.lockb");

    let mut toml_lockfile = Lockfile::new();
    toml_lockfile.add_package(LockedPackage {
        name: "reviewed".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-reviewed".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://registry.npmjs.org/reviewed/-/reviewed-1.0.0.tgz".to_string()),
    });
    toml_lockfile.write_to_file(&toml_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut poisoned_binary = Lockfile::new();
    poisoned_binary.add_package(LockedPackage {
        name: "reviewed".to_string(),
        version: "9.9.9".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-poisoned".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec!["payload@1.0.0".to_string()],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://registry.npmjs.org/reviewed/-/reviewed-9.9.9.tgz".to_string()),
    });
    binary::write_binary(&poisoned_binary, &binary_path).unwrap();

    let result = Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(result, toml_lockfile);
}

#[test]
fn read_fast_ignores_stale_binary() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = dir.path().join("lpm.lockb");

    let lf = sample_lockfile();

    binary::write_binary(&lf, &binary_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut lf2 = Lockfile::new();
    lf2.add_package(LockedPackage {
        name: "only-in-toml".to_string(),
        version: "9.9.9".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf2.write_to_file(&toml_path).unwrap();

    let result = Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(result, lf2);
}

#[test]
fn read_fast_ignores_corrupt_binary() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = dir.path().join("lpm.lockb");

    let lf = sample_lockfile();
    lf.write_to_file(&toml_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::write(&binary_path, b"BADMxxxxxxxxxxxxxxxxx").unwrap();

    let result = Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(result, lf);
}

#[test]
fn read_fast_preserves_unsupported_binary_while_reading_toml() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");
    let binary_path = dir.path().join("lpm.lockb");

    let lf = sample_lockfile();
    lf.write_to_file(&toml_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut v1_header = Vec::with_capacity(16);
    v1_header.extend_from_slice(b"LPMB");
    v1_header.extend_from_slice(&1u32.to_le_bytes());
    v1_header.extend_from_slice(&0u32.to_le_bytes());
    v1_header.extend_from_slice(&16u32.to_le_bytes());
    std::fs::write(&binary_path, &v1_header).unwrap();

    let result = Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(result, lf);
    assert!(binary_path.exists());
}

#[test]
fn read_fast_works_with_only_toml() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("lpm.lock");

    let lf = sample_lockfile();
    lf.write_to_file(&toml_path).unwrap();

    // No binary file exists
    let binary_path = dir.path().join("lpm.lockb");
    assert!(!binary_path.exists());

    let result = Lockfile::read_fast(&toml_path).unwrap();
    assert_eq!(result, lf);
}

// ── source_kind() typed accessor ─────────────────────────────────────────

fn pkg_with_source(name: &str, source: Option<&str>) -> LockedPackage {
    LockedPackage {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: source.map(|s| s.to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    }
}

#[test]
fn source_kind_none_when_source_absent() {
    let pkg = pkg_with_source("foo", None);
    assert!(pkg.source_kind().is_none());
}

#[test]
fn source_kind_parses_existing_registry_format() {
    let pkg = pkg_with_source("react", Some("registry+https://registry.npmjs.org"));
    match pkg.source_kind() {
        Some(Ok(Source::Registry { url })) => assert_eq!(url, "https://registry.npmjs.org"),
        other => panic!("expected Registry, got {other:?}"),
    }
}

#[test]
fn source_kind_parses_lpm_registry_format() {
    let pkg = pkg_with_source("@lpm.dev/foo", Some("registry+https://lpm.dev"));
    match pkg.source_kind() {
        Some(Ok(Source::Registry { url })) => assert_eq!(url, "https://lpm.dev"),
        other => panic!("expected Registry, got {other:?}"),
    }
}

#[test]
fn source_kind_parses_tarball_url() {
    let pkg = pkg_with_source("foo", Some("tarball+https://example.com/foo-1.tgz"));
    match pkg.source_kind() {
        Some(Ok(Source::Tarball { url })) => {
            assert_eq!(url, "https://example.com/foo-1.tgz");
        }
        other => panic!("expected Tarball, got {other:?}"),
    }
}

#[test]
fn source_kind_parses_directory() {
    let pkg = pkg_with_source("foo", Some("directory+../packages/foo"));
    match pkg.source_kind() {
        Some(Ok(Source::Directory { path })) => assert_eq!(path, "../packages/foo"),
        other => panic!("expected Directory, got {other:?}"),
    }
}

#[test]
fn source_kind_parses_link() {
    let pkg = pkg_with_source("foo", Some("link+../packages/foo"));
    match pkg.source_kind() {
        Some(Ok(Source::Link { path })) => assert_eq!(path, "../packages/foo"),
        other => panic!("expected Link, got {other:?}"),
    }
}

#[test]
fn source_kind_parses_git() {
    let pkg = pkg_with_source("foo", Some("git+https://github.com/foo/bar.git"));
    match pkg.source_kind() {
        Some(Ok(Source::Git { url })) => {
            assert_eq!(url, "git+https://github.com/foo/bar.git");
        }
        other => panic!("expected Git, got {other:?}"),
    }
}

#[test]
fn source_kind_returns_err_for_unknown_kind() {
    let pkg = pkg_with_source("foo", Some("nonsense+whatever"));
    assert!(matches!(
        pkg.source_kind(),
        Some(Err(SourceParseError::UnknownKind(_)))
    ));
}

// ── tarball field-hint disjointness ──────────────────────────────────────

fn pkg_with_source_and_tarball(source: Option<&str>, tarball: Option<&str>) -> LockedPackage {
    LockedPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: source.map(|s| s.to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: tarball.map(|s| s.to_string()),
    }
}

#[test]
fn tarball_hint_consistent_when_no_source() {
    // No source set → trivially consistent (source-less packages
    // are workspace members or tombstones; the hint, if present,
    // is harmless legacy data).
    let pkg = pkg_with_source_and_tarball(None, Some("https://e.com/foo.tgz"));
    assert!(pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_hint_consistent_when_no_hint() {
    let pkg = pkg_with_source_and_tarball(Some("tarball+https://e.com/foo.tgz"), None);
    assert!(pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_hint_consistent_when_registry_source() {
    // Registry + dist-URL hint is the intended shape.
    let pkg = pkg_with_source_and_tarball(
        Some("registry+https://registry.npmjs.org"),
        Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
    );
    assert!(pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_hint_inconsistent_when_paired_with_tarball_source() {
    // The conflation case to guard against: `Source::Tarball`'s
    // URL is identity; a sibling `tarball` hint slot is ill-formed.
    let pkg = pkg_with_source_and_tarball(
        Some("tarball+https://e.com/foo.tgz"),
        Some("https://e.com/foo.tgz"),
    );
    assert!(
        !pkg.tarball_field_hint_is_consistent(),
        "Source::Tarball + tarball field-hint must be flagged inconsistent"
    );
}

#[test]
fn tarball_hint_inconsistent_when_paired_with_git_source() {
    let pkg = pkg_with_source_and_tarball(
        Some("git+https://github.com/foo/bar.git"),
        Some("https://e.com/foo.tgz"),
    );
    assert!(!pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_hint_inconsistent_when_paired_with_directory_source() {
    let pkg = pkg_with_source_and_tarball(
        Some("directory+../packages/foo"),
        Some("https://e.com/foo.tgz"),
    );
    assert!(!pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_hint_inconsistent_when_paired_with_link_source() {
    let pkg =
        pkg_with_source_and_tarball(Some("link+../packages/foo"), Some("https://e.com/foo.tgz"));
    assert!(!pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_hint_consistent_when_source_unparseable() {
    // Malformed source → not our problem here; some other validator
    // will flag the source. We don't double-flag.
    let pkg = pkg_with_source_and_tarball(Some("garbage"), Some("https://e.com/foo.tgz"));
    assert!(pkg.tarball_field_hint_is_consistent());
}

#[test]
fn tarball_field_hint_round_trips_through_toml_with_registry() {
    // The full-shape TOML round-trip with both source AND tarball
    // hint set must survive serialization unchanged.
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("registry+https://registry.npmjs.org"),
        Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
    ));
    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("parse");
    assert_eq!(parsed, lf);
    assert!(parsed.packages[0].tarball_field_hint_is_consistent());
}

#[test]
fn tarball_source_round_trips_through_toml_without_hint() {
    // A `Source::Tarball` package must NOT carry a tarball hint
    // through the round-trip — the parser preserves the shape we
    // wrote (no hint), and the consistency check stays green.
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("tarball+https://e.com/foo-1.0.0.tgz"),
        None,
    ));
    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("parse");
    assert_eq!(parsed, lf);
    assert!(parsed.packages[0].tarball_field_hint_is_consistent());
    assert!(parsed.packages[0].tarball.is_none());
    match parsed.packages[0].source_kind() {
        Some(Ok(Source::Tarball { .. })) => {}
        other => panic!("expected Tarball source, got {other:?}"),
    }
}

// ── Non-registry source round-trip coverage ───────────────────────────────

#[test]
fn directory_source_round_trips_through_toml() {
    // `Source::Directory { path }` — file: directory dep.
    // Wire-format `directory+<rel-path>` survives serialize +
    // parse; disjointness invariant holds (no tarball hint).
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("directory+./packages/foo"),
        None,
    ));
    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("parse");
    assert_eq!(parsed, lf);
    assert!(parsed.packages[0].tarball_field_hint_is_consistent());
    assert!(parsed.packages[0].tarball.is_none());
    match parsed.packages[0].source_kind() {
        Some(Ok(Source::Directory { path })) => {
            assert_eq!(path, "./packages/foo");
        }
        other => panic!("expected Directory source, got {other:?}"),
    }
}

#[test]
fn link_source_round_trips_through_toml() {
    // `Source::Link { path }` — link: dep. Same shape as
    // Directory but with `link+` wire prefix.
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("link+../shared/util"),
        None,
    ));
    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("parse");
    assert_eq!(parsed, lf);
    assert!(parsed.packages[0].tarball_field_hint_is_consistent());
    match parsed.packages[0].source_kind() {
        Some(Ok(Source::Link { path })) => {
            assert_eq!(path, "../shared/util");
        }
        other => panic!("expected Link source, got {other:?}"),
    }
}

#[test]
fn tarball_local_source_round_trips_through_toml_with_sha256_integrity() {
    // `Source::Tarball { url: "file:..." }` — local-file tarball.
    // The wire format reuses `tarball+` for both remote and local;
    // the URL prefix is what disambiguates downstream. Integrity is sha256 (computed
    // from the bytes at install time), distinct from the sha512
    // SRI typically used for remote registry tarballs.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "local-bundle".to_string(),
        version: "1.0.0".to_string(),
        source: Some("tarball+file:./vendor/local-bundle-1.0.0.tgz".to_string()),
        integrity: Some("sha256-abc123def456".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("parse");
    assert_eq!(parsed, lf);
    // tarball field-hint stays None for non-Registry sources.
    assert!(parsed.packages[0].tarball.is_none());
    assert!(parsed.packages[0].tarball_field_hint_is_consistent());
    // Integrity preserved exactly.
    assert_eq!(
        parsed.packages[0].integrity.as_deref(),
        Some("sha256-abc123def456"),
    );
    // The URL retains the file: prefix — this is what install.rs's
    // `store_path_source_aware` route discrimination depends on.
    match parsed.packages[0].source_kind() {
        Some(Ok(Source::Tarball { url })) => {
            assert!(
                url.starts_with("file:"),
                "local-tarball URL must keep file: prefix, got {url:?}",
            );
        }
        other => panic!("expected Tarball source, got {other:?}"),
    }
}

#[test]
fn directory_link_sources_share_lockfile_with_registry_packages() {
    // Mixed-source lockfile: registry + tarball (remote) + tarball
    // (local) + directory + link, all in one graph. Round-trip
    // preserves every package's source identity. Exercises the
    // identity model end-to-end at the lockfile layer.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-lodash".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
    });
    lf.add_package(LockedPackage {
        name: "remote-fork".to_string(),
        version: "1.0.0".to_string(),
        source: Some("tarball+https://e.com/remote-fork.tgz".to_string()),
        integrity: Some("sha512-remoteFork".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "local-tarball".to_string(),
        version: "1.0.0".to_string(),
        source: Some("tarball+file:./vendor/local-tarball.tgz".to_string()),
        integrity: Some("sha256-localTarball".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "local-dir".to_string(),
        version: "0.1.0".to_string(),
        source: Some("directory+./packages/local-dir".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "linked".to_string(),
        version: "0.1.0".to_string(),
        source: Some("link+../shared/linked".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });

    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("parse");
    assert_eq!(parsed.packages.len(), 5);
    // Every package's source variant survives the round-trip.
    for pkg in &parsed.packages {
        assert!(
            pkg.source_kind().as_ref().is_some_and(|r| r.is_ok()),
            "source must parse for {}: got {:?}",
            pkg.name,
            pkg.source_kind(),
        );
        // Disjointness invariant holds across all sources.
        assert!(
            pkg.tarball_field_hint_is_consistent(),
            "tarball-hint disjointness violation for {}: {:?}",
            pkg.name,
            pkg,
        );
    }
    assert_eq!(parsed, lf);
}

#[test]
fn from_toml_rejects_directory_source_with_tarball_hint() {
    // directory+ source + tarball field-hint is a hard reject at
    // lockfile-load time. The hint is registry-specific (dist-URL
    // cache); for non-Registry sources, conflation could let
    // `lpm update` silently swap the dep.
    let toml = lockfile_with_bad_pair(
        "foo",
        "directory+./packages/foo",
        "https://anywhere.com/foo.tgz",
    );
    match Lockfile::from_toml(&toml) {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "foo");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

#[test]
fn from_toml_rejects_link_source_with_tarball_hint() {
    let toml = lockfile_with_bad_pair(
        "linked",
        "link+./packages/linked",
        "https://anywhere.com/linked.tgz",
    );
    match Lockfile::from_toml(&toml) {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "linked");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

// ── Lockfile-load hard reject ─────────────────────────────────────────────

/// Hand-craft a conflated lockfile TOML string. We can't go
/// through `to_toml` anymore — the writer guard refuses to
/// serialize this shape.
/// Tests that exercise the *reader* gate must produce the bytes
/// directly, simulating a corrupt or hand-edited `lpm.lock`.
fn lockfile_with_bad_pair(name: &str, source: &str, tarball: &str) -> String {
    format!(
        "[metadata]\n\
             lockfile-version = 9\n\
             resolved-with = \"pubgrub\"\n\
             \n\
             [[packages]]\n\
             name = \"{name}\"\n\
             version = \"1.0.0\"\n\
             source = \"{source}\"\n\
             tarball = \"{tarball}\"\n"
    )
}

#[test]
fn from_toml_rejects_tarball_source_with_hint_conflation() {
    let toml = lockfile_with_bad_pair(
        "foo",
        "tarball+https://e.com/foo-1.0.0.tgz",
        "https://e.com/foo-1.0.0.tgz",
    );
    match Lockfile::from_toml(&toml) {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "foo");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

#[test]
fn from_toml_rejects_git_source_with_hint_conflation() {
    let toml = lockfile_with_bad_pair(
        "foo",
        "git+https://github.com/foo/bar.git",
        "https://e.com/foo.tgz",
    );
    match Lockfile::from_toml(&toml) {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "foo");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

#[test]
fn from_toml_rejects_directory_source_with_hint_conflation() {
    let toml = lockfile_with_bad_pair("foo", "directory+../packages/foo", "https://e.com/foo.tgz");
    assert!(matches!(
        Lockfile::from_toml(&toml),
        Err(LockfileError::InvalidTarballHint { .. })
    ));
}

#[test]
fn from_toml_rejects_link_source_with_hint_conflation() {
    let toml = lockfile_with_bad_pair("foo", "link+../packages/foo", "https://e.com/foo.tgz");
    assert!(matches!(
        Lockfile::from_toml(&toml),
        Err(LockfileError::InvalidTarballHint { .. })
    ));
}

#[test]
fn from_toml_accepts_registry_source_with_hint() {
    // The intended shape — registry source plus dist-URL hint —
    // must still parse cleanly through the gate.
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("registry+https://registry.npmjs.org"),
        Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
    ));
    let toml = lf.to_toml().expect("serialize");
    Lockfile::from_toml(&toml).expect("registry+hint must parse cleanly post-gate");
}

#[test]
fn from_toml_rejects_lpm_scope_pointed_at_non_lpm_origin() {
    let toml = "[metadata]\n\
             lockfile-version = 1\n\
             \n\
             [[packages]]\n\
             name = \"@lpm.dev/alice.utils\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://registry.npmjs.org\"\n";
    match Lockfile::from_toml(toml) {
        Err(LockfileError::InvalidScopeOrigin { package, url }) => {
            assert_eq!(package, "@lpm.dev/alice.utils");
            assert_eq!(url, "https://registry.npmjs.org");
        }
        other => panic!("expected InvalidScopeOrigin, got {other:?}"),
    }
}

#[test]
fn from_toml_rejects_lpm_scope_at_lookalike_origin() {
    let toml = "[metadata]\n\
             lockfile-version = 1\n\
             \n\
             [[packages]]\n\
             name = \"@lpm.dev/alice.utils\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://lpm.dev.evil.com\"\n";
    match Lockfile::from_toml(toml) {
        Err(LockfileError::InvalidScopeOrigin { .. }) => {}
        other => panic!("expected InvalidScopeOrigin, got {other:?}"),
    }
}

#[test]
fn from_toml_accepts_lpm_scope_at_lpm_origin() {
    let toml = "[metadata]\n\
             lockfile-version = 1\n\
             \n\
             [[packages]]\n\
             name = \"@lpm.dev/alice.utils\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://lpm.dev\"\n";
    Lockfile::from_toml(toml).expect("https://lpm.dev must pass");
}

#[test]
fn from_toml_accepts_lpm_scope_at_localhost_for_dev() {
    let toml = "[metadata]\n\
             lockfile-version = 1\n\
             \n\
             [[packages]]\n\
             name = \"@lpm.dev/alice.utils\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+http://localhost:3000\"\n";
    Lockfile::from_toml(toml).expect("localhost dev origin must pass");
}

#[test]
fn from_toml_accepts_non_lpm_scope_at_any_origin() {
    let toml = "[metadata]\n\
             lockfile-version = 1\n\
             \n\
             [[packages]]\n\
             name = \"react\"\n\
             version = \"19.0.0\"\n\
             source = \"registry+https://registry.npmjs.org\"\n";
    Lockfile::from_toml(toml).expect("non-LPM-scope package must pass");
}

#[test]
fn validate_loaded_packages_rejects_binary_path_scope_mismatch() {
    let bad = LockedPackage {
        name: "@lpm.dev/alice.utils".into(),
        version: "1.0.0".into(),
        source: Some("registry+https://registry.npmjs.org".into()),
        integrity: Some("sha512-deadbeef".into()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    };
    match Lockfile::validate_loaded_packages(&[bad]) {
        Err(LockfileError::InvalidScopeOrigin { package, url }) => {
            assert_eq!(package, "@lpm.dev/alice.utils");
            assert_eq!(url, "https://registry.npmjs.org");
        }
        other => panic!("expected InvalidScopeOrigin, got {other:?}"),
    }
}

#[test]
fn from_toml_accepts_existing_lockfile_without_hint() {
    // Backward-compat: old lockfiles without a tarball hint must
    // still parse cleanly.
    let lf = sample_lockfile();
    let toml = lf.to_toml().expect("serialize");
    let parsed = Lockfile::from_toml(&toml).expect("legacy lockfile must still parse");
    assert_eq!(parsed, lf);
}

#[test]
fn from_toml_gate_runs_per_package_and_names_first_offender() {
    // Two-package hand-crafted lockfile (writer guard prevents
    // round-tripping bad shapes; we simulate corruption directly):
    // first package is the legitimate shape (Registry + hint),
    // second has the conflation. Gate must fire on the second and
    // name it correctly — not silently skip after seeing a valid
    // first.
    let toml = "[metadata]\n\
             lockfile-version = 1\n\
             resolved-with = \"pubgrub\"\n\
             \n\
             [[packages]]\n\
             name = \"good-pkg\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://registry.npmjs.org\"\n\
             tarball = \"https://registry.npmjs.org/good-pkg/-/good-pkg-1.0.0.tgz\"\n\
             \n\
             [[packages]]\n\
             name = \"bad-pkg\"\n\
             version = \"1.0.0\"\n\
             source = \"tarball+https://e.com/bad.tgz\"\n\
             tarball = \"https://e.com/bad.tgz\"\n";
    match Lockfile::from_toml(toml) {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "bad-pkg", "gate should name the offender");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

// ── Writer guard ─────────────────────────────────────────────────────────

#[test]
fn to_toml_rejects_tarball_source_with_hint_conflation() {
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("tarball+https://e.com/foo.tgz"),
        Some("https://e.com/foo.tgz"),
    ));
    match lf.to_toml() {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "foo");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

#[test]
fn to_toml_rejects_git_source_with_hint_conflation() {
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("git+https://github.com/foo/bar.git"),
        Some("https://e.com/foo.tgz"),
    ));
    assert!(matches!(
        lf.to_toml(),
        Err(LockfileError::InvalidTarballHint { .. })
    ));
}

#[test]
fn to_toml_rejects_directory_source_with_hint_conflation() {
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("directory+../packages/foo"),
        Some("https://e.com/foo.tgz"),
    ));
    assert!(matches!(
        lf.to_toml(),
        Err(LockfileError::InvalidTarballHint { .. })
    ));
}

#[test]
fn to_toml_rejects_link_source_with_hint_conflation() {
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("link+../packages/foo"),
        Some("https://e.com/foo.tgz"),
    ));
    assert!(matches!(
        lf.to_toml(),
        Err(LockfileError::InvalidTarballHint { .. })
    ));
}

#[test]
fn to_toml_accepts_registry_source_with_hint() {
    // Registry + dist-URL hint must continue to serialize cleanly
    // through the guard.
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("registry+https://registry.npmjs.org"),
        Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
    ));
    lf.to_toml().expect("registry+hint must serialize cleanly");
}

#[test]
fn to_toml_accepts_tarball_source_without_hint() {
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("tarball+https://e.com/foo.tgz"),
        None,
    ));
    lf.to_toml()
        .expect("tarball source without hint must serialize cleanly");
}

#[test]
fn to_toml_writer_guard_runs_per_package_and_names_first_offender() {
    // Two-package case mirroring the reader-side test: first OK,
    // second conflated. Writer guard must surface the second.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "good-pkg".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://registry.npmjs.org/good-pkg/-/good-pkg-1.0.0.tgz".to_string()),
    });
    lf.add_package(LockedPackage {
        name: "bad-pkg".to_string(),
        version: "1.0.0".to_string(),
        source: Some("git+https://github.com/foo/bar.git".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some("https://e.com/bad.tgz".to_string()),
    });
    match lf.to_toml() {
        Err(LockfileError::InvalidTarballHint { package }) => {
            assert_eq!(package, "bad-pkg", "writer guard should name the offender");
        }
        other => panic!("expected InvalidTarballHint, got {other:?}"),
    }
}

#[test]
fn writer_guard_prevents_serialization_of_conflated_shape() {
    // Defense-in-depth: the writer guard means a conflated
    // Lockfile in memory can never be persisted, so the
    // reader-side gate is genuinely the last line of defense
    // against external corruption (hand-edits, CI tampering),
    // not a fallback for our own writer.
    let mut lf = Lockfile::new();
    lf.add_package(pkg_with_source_and_tarball(
        Some("tarball+https://e.com/foo.tgz"),
        Some("https://e.com/foo.tgz"),
    ));
    // to_toml fails.
    assert!(lf.to_toml().is_err());
    // write_to_file (which calls to_toml) also fails — and must
    // not leak partial state.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.lock");
    let result = lf.write_to_file(&path);
    assert!(
        result.is_err(),
        "write_to_file must fail on conflated shape"
    );
    assert!(
        !path.exists(),
        "no lockfile must be written when guard fires"
    );
}

// ── Cross-source identity (PackageKey) ───────────────────────────────────

#[test]
fn package_key_distinguishes_cross_source_same_name_version() {
    // Registry react@19.0.0 and Tarball react@19.0.0 must
    // produce distinct PackageKeys — that
    // collision case being structurally prevented.
    let reg = LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    };
    let tar = LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    };

    let reg_key = reg.package_key();
    let tar_key = tar.package_key();
    assert_eq!(reg_key.name, "react");
    assert_eq!(reg_key.version, "19.0.0");
    assert_eq!(tar_key.name, "react");
    assert_eq!(tar_key.version, "19.0.0");
    assert_ne!(reg_key.source_id, tar_key.source_id);
    assert_ne!(reg_key, tar_key);
}

#[test]
fn package_key_uses_unknown_sentinel_when_source_missing() {
    let pkg = LockedPackage {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    };
    assert_eq!(pkg.package_key().source_id, PackageKey::UNKNOWN_SOURCE_ID);
}

#[test]
fn add_package_sorts_cross_source_collisions_by_triple() {
    // Two packages with same (name, version) but different sources
    // must coexist in the Vec, sorted deterministically by the
    // (name, version, source_id) triple. A name-only sort would have either dropped one or
    // returned ambiguous ordering on insert.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });

    // Both packages preserved.
    assert_eq!(lf.packages.len(), 2);
    // Sort order: registry's source_id starts with "npm-",
    // tarball's with "t-" — "npm-" < "t-" in ASCII order, so
    // registry first.
    assert!(
        lf.packages[0]
            .source
            .as_deref()
            .unwrap()
            .starts_with("registry+")
    );
    assert!(
        lf.packages[1]
            .source
            .as_deref()
            .unwrap()
            .starts_with("tarball+")
    );
}

#[test]
fn find_package_by_key_disambiguates_cross_source_collisions() {
    let mut lf = Lockfile::new();
    let registry_pkg = LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-AAAAAAAAAA==".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    };
    let tarball_pkg = LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
        integrity: Some("sha512-BBBBBBBBBB==".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    };
    let reg_key = registry_pkg.package_key();
    let tar_key = tarball_pkg.package_key();
    lf.add_package(registry_pkg);
    lf.add_package(tarball_pkg);

    // find_package_by_key returns the EXACT match, never the
    // wrong sibling under collision.
    let by_reg = lf
        .find_package_by_key(&reg_key)
        .expect("registry must be findable");
    assert!(
        by_reg.source.as_deref().unwrap().starts_with("registry+"),
        "find_package_by_key(registry-key) must return the registry pkg, not the tarball one"
    );
    assert_eq!(by_reg.integrity.as_deref(), Some("sha512-AAAAAAAAAA=="));

    let by_tar = lf
        .find_package_by_key(&tar_key)
        .expect("tarball must be findable");
    assert!(by_tar.source.as_deref().unwrap().starts_with("tarball+"));
    assert_eq!(by_tar.integrity.as_deref(), Some("sha512-BBBBBBBBBB=="));
}

// ── Peers + ambient_peer_installs round-trip ──────────────────
//
// The lockfile schema has two peer-related fields:
//   - `Lockfile.ambient_peer_installs` (canonical names of
//     auto-installed peers from the resolver).
//   - `LockedPackage.peers` (per-package peer pinning: each
//     entry is `<peer_name>@<version>`).
//
// Both are LOAD-BEARING for warm-install correctness: the v2
// store hashes peers + root-link names into its graph-key
// identity. Lockfile fast paths that drop these fields would
// produce a different graph key than the cold install, breaking
// peer-divergent link-entry isolation.
//
// These tests pin: (1) round-trip preservation through TOML
// serialization, (2) backward-compat with old lockfiles that
// have neither field, (3) binary-fast-path fallback when either
// field is non-empty.

#[test]
fn ambient_peer_installs_round_trip_through_toml() {
    // Cold-resolve writes a lockfile with two ambient peer
    // installs. Round-trip through TOML must preserve them in
    // alphabetical order.
    let mut lf = Lockfile::new();
    lf.ambient_peer_installs = vec!["react".to_string(), "@types/react".to_string()];
    // Sort here mirrors the resolver's drain-tail dedup+sort; the
    // ordering invariant is part of the contract so tests pin both
    // serialize and deserialize sides agree.
    lf.ambient_peer_installs.sort();

    let toml = lf.to_toml().expect("serialize must succeed");
    // Field present in serialized form.
    assert!(
        toml.contains("ambient-peer-installs"),
        "non-empty ambient_peer_installs must serialize: {toml}"
    );

    let restored = Lockfile::from_toml(&toml).expect("parse must succeed");
    assert_eq!(
        restored.ambient_peer_installs, lf.ambient_peer_installs,
        "ambient_peer_installs must round-trip exactly"
    );
}

#[test]
fn ambient_peer_installs_empty_skipped_in_serialization() {
    // Backward-compat: a lockfile with NO ambient peers must
    // serialize WITHOUT the `ambient-peer-installs` field, keeping
    // older lockfiles byte-identical.
    let lf = Lockfile::new();
    assert!(lf.ambient_peer_installs.is_empty());

    let toml = lf.to_toml().expect("serialize must succeed");
    assert!(
        !toml.contains("ambient-peer-installs"),
        "empty ambient_peer_installs must be skipped from serialization: {toml}"
    );
}

#[test]
fn locked_package_peers_round_trip_through_toml() {
    // A package with two peer pins survives TOML round-trip.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "react-redux".to_string(),
        version: "9.2.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec!["use-sync-external-store@1.6.0".to_string()],
        alias_dependencies: vec![],
        peers: vec!["react@18.2.0".to_string(), "redux@5.0.1".to_string()],
        tarball: None,
    });

    let toml = lf.to_toml().expect("serialize must succeed");
    assert!(
        toml.contains("peers ="),
        "non-empty peers must serialize: {toml}"
    );

    let restored = Lockfile::from_toml(&toml).expect("parse must succeed");
    let pkg = restored.find_package("react-redux").unwrap();
    assert_eq!(
        pkg.peers,
        vec!["react@18.2.0".to_string(), "redux@5.0.1".to_string()],
        "per-package peers must round-trip exactly — load-bearing for v2 \
             graph-key reproducibility on warm installs"
    );
}

#[test]
fn locked_package_peers_empty_skipped_in_serialization() {
    // Backward-compat: a package WITHOUT peers must serialize
    // WITHOUT the `peers = [...]` line, keeping older lockfiles
    // byte-identical.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });

    let toml = lf.to_toml().expect("serialize must succeed");
    assert!(
        !toml.contains("peers ="),
        "empty peers must be skipped from serialization: {toml}"
    );
}

#[test]
fn legacy_lockfile_without_peer_fields_parses_with_empty_defaults() {
    // A lockfile without `ambient-peer-installs` or `peers` fields
    // must parse cleanly — serde defaults populate both as empty
    // Vec.
    let legacy_peerless_toml = r#"
[metadata]
lockfile-version = 1
resolved-with = "greedy-fusion"

[[packages]]
name = "react"
version = "18.2.0"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-pre-r25"
dependencies = []
"#;
    let lf = Lockfile::from_toml(legacy_peerless_toml).expect("legacy lockfile must parse");
    assert!(lf.ambient_peer_installs.is_empty());
    assert_eq!(lf.packages.len(), 1);
    assert!(lf.packages[0].peers.is_empty());
}

#[test]
fn binary_format_falls_back_when_ambient_peers_present() {
    // The binary mmap format has fixed entry slots with no room
    // for peer metadata. `binary_format_supports` must return
    // false when the lockfile carries any peer state, so the
    // writer skips the binary path and the warm-install reader
    // falls back to TOML — preserving the auto-install state
    // that the binary roundtrip would silently drop.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "react".to_string(),
        version: "18.2.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    // Without peer metadata → binary format OK.
    assert!(crate::binary::binary_format_supports(&lf));

    // Now add an ambient install → binary format must reject.
    lf.ambient_peer_installs = vec!["react".to_string()];
    assert!(
        !crate::binary::binary_format_supports(&lf),
        "ambient_peer_installs must trigger binary fallback to TOML"
    );
}

#[test]
fn binary_format_falls_back_when_per_package_peers_present() {
    // Same gate, on the LockedPackage side. Even ONE package with
    // a non-empty `peers` field is enough to fall back to TOML.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "react-redux".to_string(),
        version: "9.2.0".to_string(),
        source: None,
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec!["react@18.2.0".to_string()],
        tarball: None,
    });
    assert!(
        !crate::binary::binary_format_supports(&lf),
        "per-package peers must trigger binary fallback to TOML"
    );
}

#[test]
fn auto_isolated_peer_conflicts_metadata_triggers_binary_fallback() {
    let mut lf = Lockfile::new();
    assert!(crate::binary::binary_format_supports(&lf));

    lf.metadata.auto_isolated_peer_conflicts = true;
    assert!(
        !crate::binary::binary_format_supports(&lf),
        "auto-isolated peer-conflict metadata must stay in human-readable TOML"
    );
}

#[test]
fn registry_signature_metadata_triggers_binary_fallback() {
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "signed-pkg".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-signed".to_string()),
        registry_signatures: vec![LockedRegistrySignature {
            keyid: Some("SHA256:abc123".to_string()),
            sig: Some("MEUCIQDregistrySignature".to_string()),
        }],
        registry_published_at: Some("2025-01-01T00:00:00.000Z".to_string()),
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });

    assert!(
        !crate::binary::binary_format_supports(&lf),
        "registry signature metadata must stay in human-readable TOML"
    );
}

#[test]
fn legacy_find_package_returns_some_match_under_collision() {
    // Documents the pre-existing name-only behavior: returns
    // *some* match but doesn't disambiguate. Callers that need
    // disambiguation must use find_package_by_key.
    let mut lf = Lockfile::new();
    lf.add_package(LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.add_package(LockedPackage {
        name: "react".to_string(),
        version: "19.0.0".to_string(),
        source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,

        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    // Returns *some* react entry. Don't depend on which one.
    let found = lf.find_package("react");
    assert!(found.is_some());
}

fn importer_lockfile(package_name: &str, peer_version: &str) -> Lockfile {
    let mut lockfile = Lockfile::new();
    lockfile.add_package(LockedPackage {
        name: package_name.to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        peers: vec![format!("runtime@{peer_version}")],
        ..LockedPackage::default()
    });
    lockfile.root_resolutions.insert(
        package_name.to_string(),
        LockedRootResolution {
            package: package_name.to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
        },
    );
    lockfile
        .importers
        .insert(".".to_string(), ImporterSnapshot::default());
    lockfile
}

#[test]
fn workspace_union_round_trips_distinct_importer_peer_contexts() {
    let mut union = Lockfile::new();
    union
        .absorb_importer("packages/one", importer_lockfile("plugin", "1.0.0"))
        .unwrap();
    union
        .absorb_importer("packages/two", importer_lockfile("plugin", "2.0.0"))
        .unwrap();

    assert_eq!(union.workspace_packages.len(), 2);
    let encoded = union.to_toml().expect("serialize workspace union");
    let decoded = Lockfile::from_toml(&encoded).expect("parse workspace union");
    assert_eq!(decoded, union);
    assert_eq!(
        decoded.project_importer("packages/one").unwrap().packages[0].peers,
        ["runtime@1.0.0"]
    );
    assert_eq!(
        decoded.project_importer("packages/two").unwrap().packages[0].peers,
        ["runtime@2.0.0"]
    );
}

#[test]
fn workspace_union_serialization_is_independent_of_importer_insertion_order() {
    let mut forward = Lockfile::new();
    forward
        .absorb_importer("packages/a", importer_lockfile("a", "1.0.0"))
        .unwrap();
    forward
        .absorb_importer("packages/b", importer_lockfile("b", "2.0.0"))
        .unwrap();

    let mut reverse = Lockfile::new();
    reverse
        .absorb_importer("packages/b", importer_lockfile("b", "2.0.0"))
        .unwrap();
    reverse
        .absorb_importer("packages/a", importer_lockfile("a", "1.0.0"))
        .unwrap();

    assert_eq!(forward.to_toml().unwrap(), reverse.to_toml().unwrap());
}

#[test]
fn workspace_union_rejects_missing_duplicate_and_unreachable_package_ids() {
    let mut missing = Lockfile::new();
    missing
        .absorb_importer("packages/a", importer_lockfile("a", "1.0.0"))
        .unwrap();
    missing
        .importers
        .get_mut("packages/a")
        .unwrap()
        .locked_packages[0] = format!("sha256:{}", "00".repeat(32));
    assert!(missing.to_toml().is_err(), "missing package id must fail");

    let mut duplicate = Lockfile::new();
    duplicate
        .absorb_importer("packages/a", importer_lockfile("a", "1.0.0"))
        .unwrap();
    let id = duplicate.importers["packages/a"].locked_packages[0].clone();
    duplicate
        .importers
        .get_mut("packages/a")
        .unwrap()
        .locked_packages
        .push(id);
    assert!(
        duplicate.to_toml().is_err(),
        "duplicate package id must fail"
    );

    let mut unreachable = Lockfile::new();
    unreachable
        .absorb_importer("packages/a", importer_lockfile("a", "1.0.0"))
        .unwrap();
    unreachable
        .importers
        .get_mut("packages/a")
        .unwrap()
        .locked_packages
        .clear();
    assert!(
        unreachable.to_toml().is_err(),
        "unreachable package row must fail"
    );
}

#[test]
fn workspace_union_rejects_parent_traversal_importer_paths() {
    let error = Lockfile::new()
        .absorb_importer("../outside", importer_lockfile("a", "1.0.0"))
        .expect_err("parent traversal importer must fail");
    assert!(
        error
            .to_string()
            .contains("invalid workspace importer path")
    );
}

#[test]
fn read_for_project_returns_the_nearest_workspace_importer_projection() {
    let directory = tempfile::tempdir().unwrap();
    let member = directory.path().join("packages/app");
    std::fs::create_dir_all(&member).unwrap();
    let mut union = Lockfile::new();
    union
        .absorb_importer("packages/app", importer_lockfile("app-dep", "1.0.0"))
        .unwrap();
    union
        .write_to_file(&directory.path().join(LOCKFILE_NAME))
        .unwrap();

    let projected = Lockfile::read_for_project(&member).unwrap();
    assert_eq!(projected.importer, "packages/app");
    assert_eq!(projected.path, directory.path().join(LOCKFILE_NAME));
    assert_eq!(projected.lockfile.packages[0].name, "app-dep");
}

#[test]
fn read_for_project_anchors_nested_directories_at_the_nearest_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let member = directory.path().join("packages/app");
    let nested = member.join("src/components");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        member.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    let mut union = Lockfile::new();
    union
        .absorb_importer("packages/app", importer_lockfile("app-dep", "1.0.0"))
        .unwrap();
    union
        .write_to_file(&directory.path().join(LOCKFILE_NAME))
        .unwrap();

    let projected = Lockfile::read_for_project(&nested).unwrap();
    assert_eq!(projected.importer, "packages/app");
    assert_eq!(projected.lockfile.packages[0].name, "app-dep");
}

#[test]
fn read_for_project_prefers_the_authoritative_workspace_projection_over_a_legacy_member_lockfile() {
    let directory = tempfile::tempdir().unwrap();
    let member = directory.path().join("packages/app");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::write(
        member.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    importer_lockfile("legacy-dep", "1.0.0")
        .write_to_file(&member.join(LOCKFILE_NAME))
        .unwrap();

    let mut union = Lockfile::new();
    union
        .absorb_importer("packages/app", importer_lockfile("root-dep", "2.0.0"))
        .unwrap();
    union
        .write_to_file(&directory.path().join(LOCKFILE_NAME))
        .unwrap();

    let projected = Lockfile::read_for_project(&member).unwrap();
    assert_eq!(projected.path, directory.path().join(LOCKFILE_NAME));
    assert_eq!(projected.importer, "packages/app");
    assert_eq!(projected.lockfile.packages[0].name, "root-dep");
}

#[test]
fn write_for_project_replaces_only_the_member_projection_and_prunes_old_rows() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("packages/first");
    let second = directory.path().join("packages/second");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let mut union = Lockfile::new();
    union
        .absorb_importer("packages/first", importer_lockfile("old", "1.0.0"))
        .unwrap();
    union
        .absorb_importer("packages/second", importer_lockfile("kept", "1.0.0"))
        .unwrap();
    union
        .write_to_file(&directory.path().join(LOCKFILE_NAME))
        .unwrap();

    Lockfile::write_for_project(&first, importer_lockfile("new", "2.0.0")).unwrap();
    let owner = Lockfile::read_from_file(&directory.path().join(LOCKFILE_NAME)).unwrap();
    assert_eq!(
        owner.project_importer("packages/first").unwrap().packages[0].name,
        "new"
    );
    assert_eq!(
        owner.project_importer("packages/second").unwrap().packages[0].name,
        "kept"
    );
    assert!(
        owner
            .workspace_packages
            .values()
            .all(|package| package.name != "old")
    );
}
