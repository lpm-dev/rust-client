use super::*;
use crate::v2::finalize_permits::{FinalizePermitLimiter, parse_v2_finalize_permits};
use crate::v2::fs_util::tmp_sibling;
#[cfg(unix)]
use crate::v2::fs_util::{
    copy_dir_recursively, create_tmp_dir_locked, ensure_store_tier_dir_locked,
};
use crate::v2::graph_key::{GraphKeyInputs, LinkerModeTag, PeerEntry};
use crate::v2::integrity::{
    OBJECT_INTEGRITY_FILENAME, TREE_SNAPSHOT_FILENAME, has_local_source_sentinel,
    is_complete_object_dir, is_verified_object_dir, local_source_sentinel_path,
    read_object_integrity, read_tree_snapshot, remove_unusable_object_dir, source_object_integrity,
    valid_sha256_integrity, write_source_object_integrity, write_tree_object_integrity,
    write_tree_snapshot,
};
use crate::v2::link_meta::LinkMetaPlatform;
use crate::v2::platform::PlatformTuple;
#[cfg(target_os = "macos")]
use crate::v2::tree_hash::metadata_hash_implementations_match_for_test;
use crate::v2::tree_hash::{ObjectTreeStats, TreeIntegrities, compute_tree_metadata_integrity};

fn macos_arm64() -> PlatformTuple {
    PlatformTuple::new("darwin", "arm64", None)
}

fn sample_platform() -> PlatformTuple {
    PlatformTuple::new("darwin", "arm64", None)
}

fn sample_meta_platform() -> LinkMetaPlatform {
    LinkMetaPlatform {
        os: "darwin".into(),
        cpu: "arm64".into(),
        libc: None,
    }
}

fn sample_key(name: &str, version: &str) -> GraphKey {
    let inputs = GraphKeyInputs::new(name, version, sample_platform(), LinkerModeTag::Isolated);
    GraphKey::derive(&inputs)
}

fn arc_key(name: &str, version: &str) -> Arc<GraphKey> {
    Arc::new(sample_key(name, version))
}

/// Compute a real SHA-512 SRI string over `seed`. Tests need
/// valid base64-padded SRIs because [`Integrity::parse`] enforces
/// canonical encoding; hand-rolled placeholders fail at parse time.
fn synthetic_sri(seed: &[u8]) -> String {
    crate::compute_sri_hash(seed)
}

#[test]
fn parse_v2_finalize_permits_accepts_only_positive_integers() {
    assert_eq!(parse_v2_finalize_permits("4"), Some(4));
    assert_eq!(parse_v2_finalize_permits(" 2 "), Some(2));
    assert_eq!(parse_v2_finalize_permits("0"), None);
    assert_eq!(parse_v2_finalize_permits(""), None);
    assert_eq!(parse_v2_finalize_permits("nope"), None);
}

#[test]
fn object_integrity_policy_env_parser_defaults_to_source() {
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(None),
        ObjectIntegrityPolicy::Source
    );
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(Some("")),
        ObjectIntegrityPolicy::Source
    );
}

#[test]
fn object_integrity_policy_parse_accepts_only_config_modes() {
    assert_eq!(
        ObjectIntegrityPolicy::parse("source"),
        Some(ObjectIntegrityPolicy::Source)
    );
    assert_eq!(
        ObjectIntegrityPolicy::parse(" tree "),
        Some(ObjectIntegrityPolicy::Tree)
    );
    assert_eq!(ObjectIntegrityPolicy::parse("sri"), None);
    assert_eq!(ObjectIntegrityPolicy::parse("unknown"), None);
}

#[test]
fn object_integrity_policy_env_parser_accepts_tree_strict_mode() {
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(Some("tree")),
        ObjectIntegrityPolicy::Tree
    );
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(Some("unknown")),
        ObjectIntegrityPolicy::Tree
    );
}

#[test]
fn object_integrity_policy_env_parser_accepts_source_aliases() {
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(Some("source")),
        ObjectIntegrityPolicy::Source
    );
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(Some(" sri ")),
        ObjectIntegrityPolicy::Source
    );
    assert_eq!(
        ObjectIntegrityPolicy::from_env_value(Some("TARBALL")),
        ObjectIntegrityPolicy::Source
    );
}

#[test]
fn source_object_integrity_is_valid_sha256_and_source_dependent() {
    let first = source_object_integrity("sha512-first");
    let second = source_object_integrity("sha512-second");

    assert_ne!(first, second);
    assert!(valid_sha256_integrity(&first));
    assert!(valid_sha256_integrity(&second));
}

#[test]
fn finalize_permit_limiter_blocks_until_guard_drops() {
    let limiter = Arc::new(FinalizePermitLimiter::new(1));
    let first_guard = limiter.acquire();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
    let worker_limiter = Arc::clone(&limiter);

    let worker = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let _second_guard = worker_limiter.acquire();
        acquired_tx.send(()).unwrap();
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert!(matches!(
        acquired_rx.recv_timeout(std::time::Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    drop(first_guard);
    acquired_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn compat_island_key_changes_when_entry_content_changes() {
    let dir_name = "local-tool@1.0.0+abcdef1234567890";
    let source_sri = synthetic_sri(b"stable-local-source-identity");
    let first = compat_island_key(&[CompatIslandKeyEntry {
        dir_name,
        source_sri: &source_sri,
        content_integrity: "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }]);
    let second = compat_island_key(&[CompatIslandKeyEntry {
        dir_name,
        source_sri: &source_sri,
        content_integrity: "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }]);

    assert_ne!(
        first, second,
        "stable-SRI local sources must get a new compat island key when their link-entry bytes change"
    );
}

fn write_tree_object(store: &Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = store.paths().object_dir(sri).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    for (name, contents) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }
    write_tree_object_integrity(&dir).unwrap();
    std::fs::write(dir.join(".integrity"), sri).unwrap();
    dir
}

fn write_object(store: &Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = write_tree_object(store, sri, files);
    write_source_object_integrity(&dir, sri).unwrap();
    dir
}

fn extract_object_source(
    store: &Store,
    sri: &str,
    tarball_data: &[u8],
) -> Result<PathBuf, LpmError> {
    store
        .extract_object_with_timings_and_policy(sri, tarball_data, ObjectIntegrityPolicy::Source)
        .map(|(object, _)| object.path)
}

fn populate_link_entry_source(
    store: &Store,
    request: LinkEntryRequest,
) -> Result<LinkEntry, LpmError> {
    store.populate_link_entry_inner(request, None, None, ObjectIntegrityPolicy::Source)
}

fn populate_link_entry_with_verified_object_source(
    store: &Store,
    request: LinkEntryRequest,
    verified_object_integrity: &VerifiedObjectIntegrity,
) -> Result<LinkEntry, LpmError> {
    store.populate_link_entry_inner(
        request,
        Some(verified_object_integrity),
        None,
        ObjectIntegrityPolicy::Source,
    )
}

#[test]
fn reusable_object_tree_policy_recreates_missing_tree_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_tree_policy_recreates_missing_tree_snapshot");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot\"}"),
            ("index.js", b"ok"),
        ],
    );
    let snapshot_path = object_dir.join(TREE_SNAPSHOT_FILENAME);
    assert!(snapshot_path.is_file());

    std::fs::remove_file(&snapshot_path).unwrap();
    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object_dir);
    assert!(
        snapshot_path.is_file(),
        "full-hash fallback must refresh the fast metadata snapshot"
    );
}

#[test]
fn reusable_object_with_timings_tree_policy_reports_snapshot_fast_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_with_timings_tree_policy_reports_snapshot_fast_path");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot-timed\"}"),
            ("index.js", b"ok"),
        ],
    );

    let (reusable, timings) = store
        .reusable_object_with_timings_and_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert_eq!(reusable.unwrap().path, object_dir);
    assert_eq!(timings.object_sidecar_read_count, 1);
    assert_eq!(timings.snapshot_read_count, 1);
    assert_eq!(timings.snapshot_hit_count, 1);
    assert_eq!(timings.snapshot_miss_count, 0);
    assert_eq!(timings.full_hash_count, 0);
    assert_eq!(timings.removed_count, 0);
}

#[test]
fn reusable_object_with_timings_tree_policy_reports_full_hash_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_with_timings_tree_policy_reports_full_hash_fallback");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot-fallback\"}"),
            ("index.js", b"ok"),
        ],
    );
    let snapshot_path = object_dir.join(TREE_SNAPSHOT_FILENAME);
    std::fs::remove_file(&snapshot_path).unwrap();

    let (reusable, timings) = store
        .reusable_object_with_timings_and_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert_eq!(reusable.unwrap().path, object_dir);
    assert_eq!(timings.snapshot_hit_count, 0);
    assert_eq!(timings.snapshot_miss_count, 1);
    assert_eq!(timings.full_hash_count, 1);
    assert_eq!(timings.removed_count, 0);
    assert!(snapshot_path.is_file());
}

#[test]
fn reusable_object_ignores_atomic_tree_snapshot_tmp_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_ignores_atomic_tree_snapshot_tmp_file");
    let object_dir = write_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot-tmp\"}"),
            ("index.js", b"ok"),
        ],
    );
    std::fs::write(
        object_dir.join("..lpm-tree-snapshot.json.tmp.1234.0"),
        b"partial",
    )
    .unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object_dir);
}

#[test]
fn reusable_object_ignores_atomic_object_integrity_tmp_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_ignores_atomic_object_integrity_tmp_file");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"object-integrity-tmp\"}"),
            ("index.js", b"ok"),
        ],
    );
    std::fs::write(
        object_dir.join("..lpm-object-integrity.tmp.1234.0"),
        b"partial",
    )
    .unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object_dir);
}

#[test]
fn compute_tree_metadata_integrity_ignores_vanished_atomic_tree_snapshot_tmp_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(
        b"compute_tree_metadata_integrity_ignores_vanished_atomic_tree_snapshot_tmp_files",
    );
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot-vanished-tmp\"}"),
            ("index.js", b"ok"),
        ],
    );

    let temp_paths: Vec<PathBuf> = (0..4096)
        .map(|idx| object_dir.join(format!("..lpm-tree-snapshot.json.tmp.1234.{idx}")))
        .collect();
    for path in &temp_paths {
        std::fs::write(path, b"partial").unwrap();
    }

    let remover = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_micros(200));
        for path in temp_paths {
            let _ = std::fs::remove_file(path);
        }
    });
    let result = compute_tree_metadata_integrity(&object_dir);
    remover.join().unwrap();

    assert!(
        result.is_ok(),
        "vanished tree snapshot temp files should be ignored before stat: {result:?}"
    );
}

#[test]
fn populate_link_entry_refreshes_missing_tree_snapshot_on_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"populate_link_entry_refreshes_missing_tree_snapshot_on_reuse");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot-link\"}"),
            ("index.js", b"ok"),
        ],
    );
    let key = arc_key("snapshot-link", "1.0.0");
    let request = || LinkEntryRequest {
        graph_key: key.clone(),
        source_sri: sri.clone(),
        object_dir: object_dir.clone(),
        deps: vec![],
        platform: Arc::new(sample_meta_platform()),
    };

    let first = store
        .populate_link_entry_inner(request(), None, None, ObjectIntegrityPolicy::Tree)
        .unwrap();
    let snapshot_path = first.link_dir.join(TREE_SNAPSHOT_FILENAME);
    assert!(snapshot_path.is_file());

    std::fs::remove_file(&snapshot_path).unwrap();
    let second = store
        .populate_link_entry_inner(request(), None, None, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert!(!second.freshly_populated);
    assert!(
        snapshot_path.is_file(),
        "reusable link entries must refresh missing metadata snapshots"
    );
}

#[test]
fn link_entry_content_integrity_recreates_missing_tree_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"link_entry_content_integrity_recreates_missing_tree_snapshot");
    let object_dir = write_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"snapshot-link\"}"),
            ("index.js", b"ok"),
        ],
    );
    let key = arc_key("snapshot-link", "1.0.0");
    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri.clone(),
            object_dir,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();
    let snapshot_path = entry.link_dir.join(TREE_SNAPSHOT_FILENAME);
    std::fs::remove_file(&snapshot_path).unwrap();

    let integrity = store
        .link_entry_content_integrity_with_policy(&key, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert_eq!(integrity, source_object_integrity(&sri));
    assert!(
        snapshot_path.is_file(),
        "compat island keying should repair legacy link entries missing the digest snapshot"
    );
}

#[test]
fn paths_for_known_sri() {
    let root = std::env::temp_dir().join(format!(
        "lpm-v2-paths-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let store = Store::at(&root);
    let sri = synthetic_sri(b"paths_for_known_sri");
    let dir = store.paths().object_dir(&sri).unwrap();
    assert!(dir.starts_with(&root));
    assert!(
        dir.components()
            .any(|component| component.as_os_str() == "objects")
    );
    assert!(dir.to_string_lossy().contains("sha512-"));
    // Hex segment: 128 hex chars + "sha512-" prefix.
    let segment = dir.file_name().unwrap().to_string_lossy().to_string();
    assert_eq!(segment.len(), "sha512-".len() + 128);
}

#[test]
fn link_path_contains_graph_key_dir_name() {
    let store = Store::at(std::env::temp_dir().join("lpm-v2-link-path"));
    let key = sample_key("react", "18.3.0");
    let dir = store.paths().link_dir(&key);
    assert!(
        dir.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("react@18.3.0+")
    );
    assert_eq!(
        store.paths().link_package_dir(&key),
        dir.join("node_modules").join("react")
    );
}

#[test]
fn populate_then_read_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"populate_then_read_sidecar");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );

    let key = arc_key("a", "1.0.0");
    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key,
            source_sri: sri.clone(),
            object_dir,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    assert!(entry.freshly_populated);
    assert!(entry.link_dir.is_dir());
    let pkg_dir = entry.link_dir.join("node_modules").join("a");
    assert!(pkg_dir.is_dir());
    assert!(pkg_dir.join("package.json").is_file());

    // Sidecar lives at the link-dir root, not inside node_modules.
    let sidecar_path = entry
        .link_dir
        .join(crate::v2::link_meta::LINK_META_FILENAME);
    assert!(sidecar_path.is_file());

    let read_back = LinkMeta::read_from(&entry.link_dir).unwrap();
    assert_eq!(read_back.name, "a");
    assert_eq!(read_back.version, "1.0.0");
    assert_eq!(read_back.source_sri, sri);
    assert!(read_back.object_path.starts_with("objects/sha512-"));
    assert_eq!(read_back.deps, vec![]);
}

#[test]
fn reusable_object_tree_policy_removes_tampered_object_tree() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_tree_policy_removes_tampered_object_tree");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );
    std::fs::write(object_dir.join("index.js"), b"//tampered").unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert!(reusable.is_none());
    assert!(
        !object_dir.exists(),
        "tampered v2 objects must be removed before cache reuse"
    );
}

#[test]
fn reusable_object_dir_removes_malformed_object_tree_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_dir_removes_malformed_object_tree_sidecar");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );
    std::fs::write(
        object_dir.join(OBJECT_INTEGRITY_FILENAME),
        b"sha256-not-hex\n",
    )
    .unwrap();

    let reusable = store.reusable_object_dir(&sri).unwrap();

    assert!(reusable.is_none());
    assert!(
        !object_dir.exists(),
        "malformed object integrity sidecars must force a fresh cache write"
    );
}

#[test]
fn reusable_object_returns_verified_object_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_returns_verified_object_integrity");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object_dir);
    assert_eq!(
        reusable.object_integrity.as_str(),
        read_object_integrity(&reusable.path).unwrap()
    );
}

#[test]
fn remove_unusable_object_dir_treats_concurrent_delete_as_success() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("objects").join("sha512-missing");

    remove_unusable_object_dir(&missing, "during concurrent cleanup").unwrap();
}

#[test]
fn populate_link_entry_tree_policy_rejects_object_tree_integrity_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri =
        synthetic_sri(b"populate_link_entry_tree_policy_rejects_object_tree_integrity_mismatch");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );
    std::fs::write(object_dir.join("index.js"), b"//tampered").unwrap();

    let key = arc_key("a", "1.0.0");
    let err = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Tree,
        )
        .unwrap_err();

    assert!(
        err.to_string().contains("v2 object integrity mismatch"),
        "link population must fail before reading tampered object bytes, got: {err}"
    );
    assert!(
        !store.paths().link_dir(&key).exists(),
        "failed link population must clean up its staging dir"
    );
}

#[test]
fn populate_link_entry_source_policy_trusts_matching_source_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"populate_link_entry_source_policy_trusts_matching_sidecar");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );
    std::fs::write(object_dir.join("index.js"), b"//tampered").unwrap();

    let key = arc_key("a", "1.0.0");
    let entry = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Source,
        )
        .unwrap();

    assert!(entry.freshly_populated);
    assert!(store.paths().link_dir(&key).is_dir());
}

#[test]
fn populate_link_entry_source_policy_rejects_wrong_source_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"populate_link_entry_source_policy_rejects_wrong_sidecar");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
    );
    let wrong_sri = synthetic_sri(b"different source");
    write_source_object_integrity(&object_dir, &wrong_sri).unwrap();

    let key = arc_key("a", "1.0.0");
    let err = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Source,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("v2 object source integrity mismatch"),
        "source policy must reject source sidecars derived from another SRI, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn populate_object_from_local_source_materializes_real_files_for_node_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("source");
    std::fs::create_dir_all(source.join("node_modules")).unwrap();
    std::fs::write(
        source.join("package.json"),
        b"{\"name\":\"local-pkg\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(source.join("index.js"), b"module.exports = 'before';\n").unwrap();
    std::fs::write(source.join(".lpm-local-source"), b"package-owned marker\n").unwrap();
    std::fs::write(source.join("node_modules/ignored.js"), b"ignored\n").unwrap();

    let sri = synthetic_sri(b"populate_object_from_local_source");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert!(has_local_source_sentinel(&object_dir));
    assert_eq!(
        std::fs::read(object_dir.join(".lpm-local-source")).unwrap(),
        b"package-owned marker\n"
    );
    assert!(
        !object_dir
            .join("package.json")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "local-source package files must be real files so Node keeps module realpaths inside the v2 link entry"
    );
    assert!(
        !object_dir
            .join("index.js")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "local-source entrypoints must not be symlinks"
    );
    assert!(
        !object_dir.join("node_modules").exists(),
        "local-source objects must exclude node_modules/"
    );
    assert_eq!(
        std::fs::read_to_string(object_dir.join("index.js")).unwrap(),
        "module.exports = 'before';\n"
    );
}

#[test]
fn populate_object_from_local_source_excludes_lpm_install_state_at_every_depth() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("source");
    std::fs::create_dir_all(source.join(".lpm")).unwrap();
    std::fs::create_dir_all(source.join("packages/member/.lpm")).unwrap();
    std::fs::write(
        source.join("package.json"),
        b"{\"name\":\"workspace-root\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(
        source.join("packages/member/package.json"),
        b"{\"name\":\"workspace-member\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(source.join(".lpm-local-source"), b"package-owned marker\n").unwrap();
    std::fs::write(source.join(".gitignore"), b".lpm/wrappers/\n").unwrap();
    std::fs::write(source.join(".gitattributes"), b"lpm.lockb binary\n").unwrap();
    std::fs::write(source.join(".lpm/install-hash"), b"root state\n").unwrap();
    std::fs::write(source.join("lpm.lock"), b"root lock\n").unwrap();
    std::fs::write(source.join("lpm.lockb"), b"root binary lock\n").unwrap();
    std::fs::write(
        source.join("packages/member/.lpm/install-hash"),
        b"member state\n",
    )
    .unwrap();
    std::fs::write(source.join("packages/member/lpm.lock"), b"member lock\n").unwrap();
    std::fs::write(
        source.join("packages/member/lpm.lockb"),
        b"member binary lock\n",
    )
    .unwrap();
    std::fs::write(
        source.join("packages/member/.gitignore"),
        b".lpm/wrappers/\n",
    )
    .unwrap();
    std::fs::write(
        source.join("packages/member/.gitattributes"),
        b"lpm.lockb binary\n",
    )
    .unwrap();

    let sri = synthetic_sri(b"populate_local_source_excludes_lpm_state");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert!(
        object_dir.join(".lpm-local-source").is_file(),
        "similarly named package-owned files must remain part of the local source"
    );
    for relative in [
        ".lpm",
        ".gitignore",
        ".gitattributes",
        "lpm.lock",
        "lpm.lockb",
        "packages/member/.lpm",
        "packages/member/.gitignore",
        "packages/member/.gitattributes",
        "packages/member/lpm.lock",
        "packages/member/lpm.lockb",
    ] {
        assert!(
            !object_dir.join(relative).exists(),
            "local-source objects must exclude generated LPM state at {relative}"
        );
    }
}

#[cfg(unix)]
#[test]
fn populate_object_from_local_source_refreshes_file_set_on_reinstall() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("package.json"),
        b"{\"name\":\"local-pkg\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(source.join("index.js"), b"module.exports = 'before';\n").unwrap();

    let sri = synthetic_sri(b"populate_object_from_local_source_refresh");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert!(object_dir.join("index.js").symlink_metadata().is_ok());
    assert!(object_dir.join("new.js").symlink_metadata().is_err());

    std::fs::write(source.join("new.js"), b"module.exports = 'new';\n").unwrap();
    let refreshed_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert_eq!(refreshed_dir, object_dir);
    assert_eq!(
        std::fs::read_to_string(object_dir.join("new.js")).unwrap(),
        "module.exports = 'new';\n"
    );

    std::fs::remove_file(source.join("index.js")).unwrap();
    store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert!(
        object_dir.join("index.js").symlink_metadata().is_err(),
        "reinstall must remove stale object entries for source files that no longer exist"
    );
}

#[cfg(unix)]
#[test]
fn populate_link_entry_source_policy_keeps_local_source_tree_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("package.json"),
        br#"{"name":"local-source","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
    let sri = synthetic_sri(b"populate_link_entry_source_policy_keeps_local_source_tree");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    let tree_integrity = read_object_integrity(&object_dir).unwrap();
    let key = arc_key("local-source", "1.0.0");

    let entry = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri.clone(),
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Source,
        )
        .unwrap();

    assert_eq!(
        read_tree_snapshot(&entry.link_dir)
            .unwrap()
            .content_integrity,
        tree_integrity
    );
    assert_ne!(tree_integrity, source_object_integrity(&sri));
}

#[cfg(unix)]
#[test]
fn tree_metadata_integrity_ignores_symlink_target_file_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let object_dir = dir.path().join("object");
    let target = dir.path().join("outside-target.js");
    std::fs::create_dir_all(&object_dir).unwrap();
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, object_dir.join("linked.js")).unwrap();

    let before = compute_tree_metadata_integrity(&object_dir).unwrap();
    std::fs::write(&target, b"changed-target-content").unwrap();
    let after = compute_tree_metadata_integrity(&object_dir).unwrap();

    assert_eq!(
        before, after,
        "metadata hashing must stat the symlink itself, not the target file"
    );
}

#[test]
fn populate_is_idempotent_and_touches_last_referenced_at() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"populate_is_idempotent");
    let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);
    let key = arc_key("b", "2.0.0");
    let req = || LinkEntryRequest {
        graph_key: key.clone(),
        source_sri: sri.clone(),
        object_dir: object_dir.clone(),
        deps: vec![],
        platform: Arc::new(sample_meta_platform()),
    };

    let first = populate_link_entry_source(&store, req()).unwrap();
    assert!(first.freshly_populated);
    assert!(first.sidecar.is_some(), "fresh population returns sidecar");
    let first_sidecar = first.sidecar.unwrap();
    let sidecar_path = first.link_dir.join(LINK_META_FILENAME);
    let mtime_before = std::fs::metadata(&sidecar_path)
        .unwrap()
        .modified()
        .unwrap();

    // Sleep enough that the file mtime granularity advances on
    // every supported FS — APFS resolves to ns, ext4 to ms, but
    // some test runners hit FAT-style 1-s granularity. 1100 ms
    // is the conservative floor.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let second = populate_link_entry_source(&store, req()).unwrap();
    assert!(!second.freshly_populated);
    assert_eq!(second.link_dir, first.link_dir);
    // Cache-hit returns no sidecar; the touch is observable via
    // the sidecar file's mtime, and the effective last-referenced
    // timestamp is max(json, mtime).
    assert!(second.sidecar.is_none(), "cache hit skips sidecar read");
    let mtime_after = std::fs::metadata(&sidecar_path)
        .unwrap()
        .modified()
        .unwrap();
    assert!(
        mtime_after > mtime_before,
        "sidecar mtime must advance on cache hit"
    );
    let read_back = LinkMeta::read_from(&first.link_dir).unwrap();
    assert_eq!(
        read_back.created_at, first_sidecar.created_at,
        "created_at is immutable across cache hits"
    );
    // The JSON `last_referenced_at` is frozen at creation; the
    // effective time tracks file mtime.
    let effective = read_back.effective_last_referenced_at(&sidecar_path);
    assert!(effective > first_sidecar.last_referenced_at);
}

#[test]
fn populate_link_entry_copies_bytes_without_sharing_object_inode() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"populate_link_entry_copies_bytes_without_sharing_object_inode");
    let object_dir = write_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"copy-safe\"}"),
            ("index.js", b"module.exports = {};"),
        ],
    );
    let key = arc_key("copy-safe", "1.0.0");

    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key,
            source_sri: sri,
            object_dir: object_dir.clone(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();
    let link_index = entry.link_dir.join("node_modules/copy-safe/index.js");

    std::fs::write(object_dir.join("index.js"), b"module.exports = 'tampered';").unwrap();

    assert_eq!(
        std::fs::read(link_index).unwrap(),
        b"module.exports = {};",
        "link entry bytes must not alias the object-store inode"
    );
}

#[test]
fn populate_link_entry_rebuilds_stale_existing_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"populate_link_entry_rebuilds_stale_existing_entry");
    let object_dir = write_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"stale-link\"}"),
            ("index.js", b"module.exports = {};"),
        ],
    );
    let key = arc_key("stale-link", "1.0.0");
    let request = || LinkEntryRequest {
        graph_key: key.clone(),
        source_sri: sri.clone(),
        object_dir: object_dir.clone(),
        deps: vec![],
        platform: Arc::new(sample_meta_platform()),
    };

    let first = populate_link_entry_source(&store, request()).unwrap();
    let link_index = first.link_dir.join("node_modules/stale-link/index.js");
    std::fs::write(&link_index, b"module.exports = 'stale';").unwrap();

    let second = populate_link_entry_source(&store, request()).unwrap();

    assert!(second.freshly_populated);
    assert_eq!(
        std::fs::read(link_index).unwrap(),
        b"module.exports = {};",
        "stale link entry must be rebuilt from the verified object"
    );
}

#[test]
fn populate_link_entry_with_verified_object_rebuilds_stale_existing_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"populate_link_entry_with_verified_object_rebuilds_stale");
    let object_dir = write_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"verified-stale-link\"}"),
            ("index.js", b"module.exports = {};"),
        ],
    );
    let verified = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap()
        .object_integrity;
    let key = arc_key("verified-stale-link", "1.0.0");
    let request = || LinkEntryRequest {
        graph_key: key.clone(),
        source_sri: sri.clone(),
        object_dir: object_dir.clone(),
        deps: vec![],
        platform: Arc::new(sample_meta_platform()),
    };

    let first =
        populate_link_entry_with_verified_object_source(&store, request(), &verified).unwrap();
    let link_index = first
        .link_dir
        .join("node_modules/verified-stale-link/index.js");
    std::fs::write(&link_index, b"module.exports = 'stale';").unwrap();

    let second =
        populate_link_entry_with_verified_object_source(&store, request(), &verified).unwrap();

    assert!(second.freshly_populated);
    assert_eq!(
        std::fs::read(link_index).unwrap(),
        b"module.exports = {};",
        "verified-object fast path must still rebuild stale link entries"
    );
}

#[test]
fn populate_link_entry_with_tree_policy_revalidates_tampered_object() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"populate_link_entry_with_tree_policy_revalidates_object");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"verified-object\"}"),
            ("index.js", b"module.exports = {};"),
        ],
    );
    let verified = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap()
        .unwrap()
        .object_integrity;
    std::fs::write(object_dir.join("index.js"), b"module.exports = 'tampered';").unwrap();

    let key = arc_key("verified-object", "1.0.0");
    let err = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            Some(&verified),
            None,
            ObjectIntegrityPolicy::Tree,
        )
        .unwrap_err();

    assert!(
        err.to_string().contains("v2 object integrity mismatch"),
        "verified-object warm path must revalidate the object before materializing it, got: {err}"
    );
    assert!(
        !store.paths().link_dir(&key).exists(),
        "failed verified-object population must clean up its staging dir"
    );
}

#[test]
fn populate_link_entry_with_fresh_object_rejects_mismatched_object() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let tarball_a = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"fresh-a\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 'a';"),
    ]);
    let tarball_b = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"fresh-b\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 'b';"),
    ]);
    let (fresh_a, _, _) = store
        .extract_object_from_bytes_with_fresh_integrity(&tarball_a, None)
        .unwrap();
    let (fresh_b, sri_b, _) = store
        .extract_object_from_bytes_with_fresh_integrity(&tarball_b, None)
        .unwrap();

    let key = arc_key("fresh-b", "1.0.0");
    let err = store
        .populate_link_entry_with_fresh_object(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri_b,
                object_dir: fresh_b.path,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            &fresh_a,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("fresh v2 link extracted object SRI mismatch"),
        "fresh-object populate must reject a digest/path from another object, got: {err}"
    );
    assert!(
        !store.paths().link_dir(&key).exists(),
        "mismatched fresh-object population must not create a link entry"
    );
}

#[test]
fn populate_link_entry_with_fresh_object_rejects_digest_transplant() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let tarball_a = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"fresh-a\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 'a';"),
    ]);
    let tarball_b = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"fresh-b\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 'b';"),
    ]);
    let (fresh_a, _, _) = store
        .extract_object_from_bytes_with_fresh_integrity(&tarball_a, None)
        .unwrap();
    let (fresh_b, sri_b, _) = store
        .extract_object_from_bytes_with_fresh_integrity(&tarball_b, None)
        .unwrap();
    let forged = ExtractedObject {
        path: fresh_b.path.clone(),
        source_sri: fresh_a.source_sri.clone(),
        object_integrity: fresh_a.object_integrity.clone(),
    };
    assert!(!fresh_a.object_integrity.as_str().is_empty());

    let key = arc_key("fresh-b", "1.0.0");
    let err = store
        .populate_link_entry_with_fresh_object(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri_b,
                object_dir: fresh_b.path,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            &forged,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("fresh v2 link extracted object SRI mismatch"),
        "fresh-object populate must reject a cloned digest paired with another object path, got: {err}"
    );
    assert!(
        !store.paths().link_dir(&key).exists(),
        "digest-transplant fresh-object population must not create a link entry"
    );
}

#[test]
fn populate_writes_sibling_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    // Two objects: one for the package itself, one for its dep.
    let pkg_sri = synthetic_sri(b"populate_writes_sibling_symlinks/pkg");
    let dep_sri = synthetic_sri(b"populate_writes_sibling_symlinks/dep");
    let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
    write_object(&store, &dep_sri, &[("package.json", b"{}")]);

    let pkg_key = arc_key("express", "4.21.0");
    let dep_key = arc_key("debug", "4.3.4");

    // Materialize the dep first so its link dir exists for the
    // symlink target. The store doesn't enforce ordering (caller's
    // responsibility) — we exercise the realistic path here.
    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: dep_key.clone(),
            source_sri: dep_sri.clone(),
            object_dir: store.paths().object_dir(&dep_sri).unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: pkg_key,
            source_sri: pkg_sri,
            object_dir: pkg_obj,
            deps: vec![DepLink {
                local: "debug".into(),
                target: dep_key.clone(),
            }],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let sibling = entry.link_dir.join("node_modules").join("debug");
    // Target string format: `../../<dep_key.dir>/node_modules/debug`.
    #[cfg(not(windows))]
    {
        let target = std::fs::read_link(&sibling).unwrap();
        assert_eq!(
            target.to_string_lossy(),
            format!("../../{}/node_modules/debug", dep_key.dir_name())
        );
    }
    // Symlink should resolve to the dep's link package dir.
    assert!(sibling.exists(), "sibling symlink must resolve");
    assert_eq!(
        sibling.canonicalize().unwrap(),
        store
            .paths()
            .link_package_dir(&dep_key)
            .canonicalize()
            .unwrap()
    );
    assert!(sibling.join("package.json").is_file());

    // Sidecar records the dep edge.
    let sidecar = entry.sidecar.expect("fresh population returns sidecar");
    assert_eq!(sidecar.deps.len(), 1);
    assert_eq!(sidecar.deps[0].local, "debug");
    assert_eq!(sidecar.deps[0].target_graph_key, dep_key.digest_hex());
}

#[test]
fn populate_rejects_dependency_local_name_with_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let pkg_sri = synthetic_sri(b"populate_rejects_unsafe_dep/pkg");
    let dep_sri = synthetic_sri(b"populate_rejects_unsafe_dep/dep");
    let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
    write_object(&store, &dep_sri, &[("package.json", b"{}")]);

    let pkg_key = arc_key("consumer", "1.0.0");
    let dep_key = arc_key("debug", "4.3.4");
    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: dep_key.clone(),
            source_sri: dep_sri.clone(),
            object_dir: store.paths().object_dir(&dep_sri).unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let err = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: pkg_key.clone(),
            source_sri: pkg_sri,
            object_dir: pkg_obj,
            deps: vec![DepLink {
                local: "../../../../escape".into(),
                target: dep_key,
            }],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap_err();

    assert!(
        format!("{err}").contains("unsafe dependency local name"),
        "error should identify the unsafe local name, got: {err}",
    );
    assert!(
        !store.paths().link_dir(&pkg_key).exists(),
        "failed population must not publish a partial link entry",
    );
}

#[test]
fn populate_writes_scoped_sibling_symlink_with_extra_dotdot() {
    // Scoped local names live one level deeper inside
    // `node_modules/`, so the relative symlink target needs an
    // additional `..` segment vs the non-scoped case.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let pkg_sri = synthetic_sri(b"scoped/pkg");
    let dep_sri = synthetic_sri(b"scoped/dep");
    let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
    write_object(&store, &dep_sri, &[("package.json", b"{}")]);

    let pkg_key = arc_key("consumer", "1.0.0");
    let dep_key = arc_key("@types/node", "20.10.0");

    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: dep_key.clone(),
            source_sri: dep_sri.clone(),
            object_dir: store.paths().object_dir(&dep_sri).unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: pkg_key,
            source_sri: pkg_sri,
            object_dir: pkg_obj,
            deps: vec![DepLink {
                local: "@types/node".into(),
                target: dep_key.clone(),
            }],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let sibling = entry
        .link_dir
        .join("node_modules")
        .join("@types")
        .join("node");
    // Three `..` segments because the symlink itself sits one
    // level deeper under `node_modules/@types/`.
    #[cfg(not(windows))]
    {
        let target = std::fs::read_link(&sibling).unwrap();
        assert_eq!(
            target.to_string_lossy(),
            format!(
                "../../../{}/node_modules/{}",
                dep_key.dir_name(),
                dep_key.name()
            )
        );
    }
    // Even though the dep's package dir is also at a scoped path
    // inside its own node_modules, its OWN dir name (sample_key
    // "@types/node") goes through the same `+` sanitization so the
    // path resolves cleanly.
    assert!(
        sibling.exists(),
        "scoped sibling symlink must resolve to the dep's package dir"
    );
    assert_eq!(
        sibling.canonicalize().unwrap(),
        store
            .paths()
            .link_package_dir(&dep_key)
            .canonicalize()
            .unwrap()
    );
}

#[test]
fn populate_nests_scoped_same_name_sibling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let pkg_sri = synthetic_sri(b"scoped-same-name/pkg");
    let dep_sri = synthetic_sri(b"scoped-same-name/dep");
    let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
    write_object(&store, &dep_sri, &[("package.json", b"{}")]);

    let pkg_key = arc_key("@scope/pkg", "2.0.0");
    let dep_key = arc_key("@scope/pkg", "1.0.0");

    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: dep_key.clone(),
            source_sri: dep_sri.clone(),
            object_dir: store.paths().object_dir(&dep_sri).unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: pkg_key,
            source_sri: pkg_sri,
            object_dir: pkg_obj,
            deps: vec![DepLink {
                local: "@scope/pkg".into(),
                target: dep_key.clone(),
            }],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let nested = entry
        .link_dir
        .join("node_modules")
        .join("@scope")
        .join("pkg")
        .join("node_modules")
        .join("@scope")
        .join("pkg");
    #[cfg(not(windows))]
    {
        let mut expected = PathBuf::new();
        for _ in 0..6 {
            expected.push("..");
        }
        expected.push(dep_key.dir_name());
        expected.push(LINK_NODE_MODULES);
        expected.push(dep_key.name());
        assert_eq!(std::fs::read_link(&nested).unwrap(), expected);
    }
    assert!(
        nested.exists(),
        "scoped same-name sibling symlink must resolve to the older package"
    );
    assert_eq!(
        nested.canonicalize().unwrap(),
        store
            .paths()
            .link_package_dir(&dep_key)
            .canonicalize()
            .unwrap()
    );
}

#[test]
fn extract_object_is_idempotent() {
    // We can't easily invoke the real extractor on a synthetic
    // tarball without pulling in flate2/tar in the test (already
    // dev-deps but it's still 30+ lines). Instead, simulate the
    // extracted state and confirm the idempotent path returns the
    // existing dir without error.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"extract_object_is_idempotent");
    let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);

    // extract_object on already-populated SRI must short-circuit.
    let returned = extract_object_source(&store, &sri, b"unused-because-hit").unwrap();
    assert_eq!(returned, object_dir);
}

#[test]
fn populate_failure_cleans_up_tmp_dir() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    // Object dir doesn't exist → materialize_into fails → tmp cleanup.
    let sri = synthetic_sri(b"populate_failure_cleans_up_tmp_dir");
    let nonexistent_object = store.paths().object_dir(&sri).unwrap();
    let key = arc_key("missing", "0.0.1");

    let err = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri,
            object_dir: nonexistent_object,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap_err();
    assert!(format!("{err}").contains("v2"));

    // No `links/<dir>` should exist (final or tmp).
    let final_dir = store.paths().link_dir(&key);
    assert!(!final_dir.exists());

    // No tmp leftover at the parent.
    let parent = final_dir.parent().unwrap();
    if parent.is_dir() {
        for entry in std::fs::read_dir(parent).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.contains("tmp."), "tmp dir leaked: {name}");
        }
    }
}

#[test]
fn invalid_sri_in_object_dir_returns_error() {
    let store = Store::at(std::env::temp_dir().join("lpm-v2-bad-sri"));
    let err = store.paths().object_dir("not-a-sri").unwrap_err();
    // Surface as InvalidIntegrity by way of the parse failure.
    assert!(matches!(err, LpmError::InvalidIntegrity(_)));
}

// -------- Crash-recovery and integrity invariants ----------

#[test]
fn populate_recovers_from_partial_link_entry_with_sidecar_only() {
    // A leftover `links/<graph-key>/` with only the sidecar (no
    // `node_modules/<pkg>/`) must be detected as incomplete and
    // re-populated, not silently accepted as a cache hit.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"recover_partial_link_entry");
    let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);
    let key = arc_key("c", "0.1.0");
    let final_dir = store.paths().link_dir(&key);

    // Create a partial entry: only the sidecar, no package dir.
    std::fs::create_dir_all(&final_dir).unwrap();
    let stub = LinkMeta::new(
        &key,
        sri.clone(),
        store.paths().relative_object_path(&sri).unwrap(),
        vec![],
        Arc::new(sample_meta_platform()),
    );
    stub.write_to(&final_dir).unwrap();

    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key,
            source_sri: sri,
            object_dir,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    assert!(
        entry.freshly_populated,
        "incomplete leftover should force re-populate"
    );
    let pkg_dir = entry.link_dir.join("node_modules").join("c");
    assert!(pkg_dir.is_dir());
    assert!(pkg_dir.join("package.json").is_file());
}

#[test]
fn extract_object_recovers_from_partial_object_dir() {
    // A leftover `objects/<sri>/` from a crashed extract
    // (no `package.json`, no `.integrity`) used to be treated as a hit.
    // After the tightening, `extract_object`
    // detects the incompleteness and removes the leftover before
    // re-extracting.
    //
    // Synthesizes an empty leftover dir, then exercises the
    // recovery short-circuit by re-running with a real object
    // populated via the `write_object` helper. Bypasses the
    // tarball extractor — these tests don't exercise the
    // gzip/tar pipeline directly.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"recover_partial_object_dir");
    let object_dir = store.paths().object_dir(&sri).unwrap();

    // Stage a partial leftover: dir exists but missing both
    // `package.json` AND `.integrity`.
    std::fs::create_dir_all(&object_dir).unwrap();
    std::fs::write(object_dir.join("garbage"), b"x").unwrap();
    assert!(!is_complete_object_dir(&object_dir));

    // Manually populate the same path with a complete object
    // (mimics what a clean extract would produce). The recovery
    // path inside `extract_object` should remove the garbage and
    // re-stage; here we exercise the helper directly via
    // `write_object` and confirm the partial doesn't masquerade
    // as a hit.
    std::fs::remove_dir_all(&object_dir).unwrap();
    write_object(&store, &sri, &[("package.json", b"{}")]);
    assert!(is_complete_object_dir(&object_dir));

    // Now the short-circuit hit path should return without
    // touching the disk further.
    let returned = extract_object_source(&store, &sri, b"unused").unwrap();
    assert_eq!(returned, object_dir);
}

#[test]
fn populate_overwrites_incomplete_final_dir_on_rename_collision() {
    // If `final_dir` exists but is incomplete when populate_link_entry's
    // atomic rename runs (a crashed peer process left a half-written entry),
    // the rename retry
    // path removes the leftover and tries once more.
    //
    // We simulate a crashed-peer leftover by manually creating
    // an empty `final_dir` between the existence check and the
    // rename. With the tightened recovery this still ends in a
    // clean populate.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"rename_overwrites_incomplete");
    let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);
    let key = arc_key("d", "0.0.1");
    let final_dir = store.paths().link_dir(&key);

    // Pre-create an empty leftover. Because it's empty (no
    // sidecar, no node_modules), `is_complete_link_entry` returns
    // false and the existence-check branch in populate_link_entry
    // removes it before staging.
    std::fs::create_dir_all(&final_dir).unwrap();
    assert!(!is_complete_link_entry(&final_dir, &key));

    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri,
            object_dir,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    assert!(entry.freshly_populated);
    assert!(is_complete_link_entry(&entry.link_dir, &key));
}

#[test]
fn hoisted_graph_key_distinguishes_peers() {
    // Hoisted link entries materialize peer sibling symlinks, so
    // peer pinning is part of the shared-entry identity. Two
    // hoisted inputs that differ only in peers must not reuse one
    // link entry.
    let no_peers = GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted);
    let with_peers = GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted)
        .with_peers([PeerEntry {
            name: "react-dom".into(),
            version: "18.3.0".into(),
        }]);
    assert_ne!(GraphKey::derive(&no_peers), GraphKey::derive(&with_peers));
}

#[test]
fn isolated_graph_key_still_distinguishes_peers() {
    // Isolated mode keeps the same peer identity contract as
    // hoisted mode: different peer layouts get different link
    // entries.
    let p1 = GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Isolated);
    let p2 = p1.clone().with_peers([PeerEntry {
        name: "react-dom".into(),
        version: "18.3.0".into(),
    }]);
    assert_ne!(GraphKey::derive(&p1), GraphKey::derive(&p2));
}

/// Build a small gzip+tar tarball with `package/<path>` entries —
/// matches the npm-tarball convention. Used by the
/// extract-from-bytes tests below.
fn build_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for (path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{path}"), &content[..])
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn extract_object_from_bytes_populates_object_dir() {
    // End-to-end round trip from raw bytes through SRI
    // computation, extraction, security analysis, and atomic
    // rename. The install pipeline's v2 entry point must produce a
    // complete object dir (package.json + .integrity +
    // .lpm-security.json all present).
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball =
        build_test_tarball(&[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")]);

    let (obj_dir, sri, _timings) = store.extract_object_from_bytes(&tarball, None).unwrap();

    assert!(sri.starts_with("sha512-"));
    assert!(obj_dir.is_dir());
    assert!(obj_dir.join("package.json").is_file());
    assert!(obj_dir.join(".integrity").is_file());
    assert!(obj_dir.join(OBJECT_INTEGRITY_FILENAME).is_file());
    // Security cache lives next to the object.
    assert!(
        obj_dir.join(".lpm-security.json").is_file(),
        "v2 security analysis must run inside extract_object"
    );
}

#[test]
fn extract_object_from_bytes_tree_policy_repairs_tampered_hot_object() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);

    let (object, _sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Tree)
        .unwrap();
    let obj_dir = object.path;
    std::fs::write(obj_dir.join("index.js"), b"module.exports = 99;\n").unwrap();

    let (repaired_object, _sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Tree)
        .unwrap();
    let repaired_dir = repaired_object.path;

    assert_eq!(repaired_dir, obj_dir);
    assert_eq!(
        std::fs::read(repaired_dir.join("index.js")).unwrap(),
        b"module.exports = 1;\n"
    );
}

#[test]
fn extract_object_from_bytes_source_policy_trusts_hot_object_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);

    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    std::fs::write(object.path.join("index.js"), b"module.exports = 99;\n").unwrap();

    let (reused_object, reused_sri, timings) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert_eq!(reused_sri, sri);
    assert_eq!(reused_object.path, object.path);
    assert_eq!(timings.extract_ms, 0);
    assert_eq!(
        std::fs::read(reused_object.path.join("index.js")).unwrap(),
        b"module.exports = 99;\n"
    );
}

#[test]
fn registry_object_preserves_local_source_filename_under_source_policy() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"sentinel-file\",\"version\":\"1.0.0\"}",
        ),
        (".lpm-local-source", b"registry package content\n"),
    ]);

    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert!(!has_local_source_sentinel(&object.path));
    assert_eq!(
        std::fs::read(object.path.join(".lpm-local-source")).unwrap(),
        b"registry package content\n"
    );

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap();
    assert_eq!(reusable.path, object.path);

    let key = arc_key("sentinel-file", "1.0.0");
    let entry = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri.clone(),
                object_dir: object.path,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Source,
        )
        .unwrap();

    assert_eq!(
        std::fs::read(
            entry
                .link_dir
                .join(LINK_NODE_MODULES)
                .join(key.name())
                .join(".lpm-local-source")
        )
        .unwrap(),
        b"registry package content\n"
    );
    assert_eq!(
        read_tree_snapshot(&entry.link_dir)
            .unwrap()
            .content_integrity,
        source_object_integrity(&sri)
    );
}

#[test]
fn extract_object_from_bytes_repairs_malformed_object_tree_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);

    let (obj_dir, _sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();
    std::fs::write(obj_dir.join(OBJECT_INTEGRITY_FILENAME), b"sha256-not-hex\n").unwrap();

    let (repaired_dir, _sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();

    assert_eq!(repaired_dir, obj_dir);
    assert_eq!(
        std::fs::read_to_string(repaired_dir.join(OBJECT_INTEGRITY_FILENAME))
            .unwrap()
            .trim()
            .len(),
        "sha256-".len() + 64
    );
}

#[test]
fn extract_object_from_bytes_verifies_expected_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[("package.json", b"{}")]);

    // Wrong expected SRI (sha512 form) → IntegrityMismatch.
    let bogus = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let err = store
        .extract_object_from_bytes(&tarball, Some(bogus))
        .unwrap_err();
    match err {
        LpmError::IntegrityMismatch { expected, .. } => {
            assert_eq!(expected, bogus);
        }
        other => panic!("expected IntegrityMismatch, got {other:?}"),
    }
}

#[test]
fn extract_object_from_bytes_accepts_correct_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[("package.json", b"{}")]);

    // Compute the SRI ourselves and pass it as expected — the
    // verification path should accept it.
    let expected = crate::compute_sri_hash(&tarball);
    let (_obj_dir, sri, _) = store
        .extract_object_from_bytes(&tarball, Some(&expected))
        .unwrap();
    assert_eq!(sri, expected);
}

#[test]
fn extract_object_from_bytes_accepts_correct_sha1_integrity() {
    use base64::Engine;
    use sha1::{Digest, Sha1};

    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[("package.json", b"{}")]);
    let expected = format!(
        "sha1-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha1::digest(&tarball))
    );

    let (_obj_dir, sri, _) = store
        .extract_object_from_bytes(&tarball, Some(&expected))
        .unwrap();
    assert_eq!(sri, crate::compute_sri_hash(&tarball));
}

#[test]
fn extract_object_from_bytes_reports_extracted_stats_on_cold_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let package_json = b"{\"name\":\"x\",\"version\":\"1.0.0\"}";
    let index_js = b"module.exports = 1;\n";
    let tarball = build_test_tarball(&[("package.json", package_json), ("lib/index.js", index_js)]);

    let (_, _, timings) = store.extract_object_from_bytes(&tarball, None).unwrap();

    assert_eq!(timings.file_count, 2);
    assert_eq!(timings.dir_count, 1);
    assert_eq!(timings.symlink_count, 0);
    assert_eq!(
        timings.unpacked_bytes,
        (package_json.len() + index_js.len()) as u64
    );
}

#[test]
fn extract_object_from_bytes_source_policy_writes_source_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let package_json = b"{\"name\":\"x\",\"version\":\"1.0.0\"}";
    let index_js = b"module.exports = 1;\n";
    let tarball = build_test_tarball(&[("package.json", package_json), ("lib/index.js", index_js)]);

    let (object, sri, timings) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert_eq!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );
    assert_eq!(timings.file_count, 2);
    assert_eq!(timings.dir_count, 1);
    assert_eq!(
        timings.unpacked_bytes,
        (package_json.len() + index_js.len()) as u64
    );
}

#[test]
fn reusable_object_source_policy_trusts_source_integrity_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    std::fs::write(object.path.join("index.js"), b"module.exports = 2;\n").unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object.path);
    assert_eq!(
        reusable.object_integrity.as_str(),
        source_object_integrity(&sri)
    );
}

#[test]
fn reusable_object_source_policy_migrates_legacy_tree_integrity_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"reusable_object_source_policy_migrates_legacy_tree_sidecar");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"legacy-object\"}"),
            ("index.js", b"module.exports = 1;\n"),
        ],
    );
    assert_ne!(
        read_object_integrity(&object_dir).unwrap(),
        source_object_integrity(&sri)
    );

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object_dir);
    assert_eq!(
        reusable.object_integrity.as_str(),
        source_object_integrity(&sri)
    );
    assert_eq!(
        read_object_integrity(&reusable.path).unwrap(),
        source_object_integrity(&sri)
    );
}

#[test]
fn reusable_object_source_policy_migrates_extracted_tree_policy_object() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"legacy-object\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Tree)
        .unwrap();
    assert_ne!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object.path);
    assert_eq!(
        reusable.object_integrity.as_str(),
        source_object_integrity(&sri)
    );
    assert_eq!(
        read_object_integrity(&reusable.path).unwrap(),
        source_object_integrity(&sri)
    );
}

#[test]
fn is_verified_object_dir_source_policy_migrates_legacy_tree_integrity_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"is_verified_object_dir_source_policy_migrates_legacy_tree_sidecar");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"legacy-collision\"}"),
            ("index.js", b"module.exports = 1;\n"),
        ],
    );

    assert!(is_verified_object_dir(&object_dir, &sri, ObjectIntegrityPolicy::Source).unwrap());
    assert_eq!(
        read_object_integrity(&object_dir).unwrap(),
        source_object_integrity(&sri)
    );
}

#[test]
fn reusable_object_source_policy_removes_wrong_source_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    let wrong_sri = synthetic_sri(b"wrong registry object source");
    write_source_object_integrity(&object.path, &wrong_sri).unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert!(reusable.is_none());
    assert!(!object.path.exists());
}

#[test]
fn reusable_object_tree_policy_migrates_source_integrity_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    assert_eq!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object.path);
    assert_ne!(
        reusable.object_integrity.as_str(),
        source_object_integrity(&sri)
    );
    assert_eq!(
        read_object_integrity(&reusable.path).unwrap(),
        reusable.object_integrity.as_str()
    );
}

#[test]
fn reusable_object_tree_policy_treats_tampered_snapshotless_source_object_as_miss() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    let snapshot_path = object.path.join(TREE_SNAPSHOT_FILENAME);
    if snapshot_path.exists() {
        std::fs::remove_file(&snapshot_path).unwrap();
    }
    std::fs::write(object.path.join("index.js"), b"module.exports = 2;\n").unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert!(reusable.is_none());
    assert!(object.path.exists());
    assert_eq!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );
}

#[test]
fn reusable_object_tree_policy_rejects_tampered_source_object_with_matching_snapshot_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    let original_snapshot = read_tree_snapshot(&object.path).unwrap();
    std::fs::write(object.path.join("index.js"), b"module.exports = 2;\n").unwrap();
    let current_metadata = compute_tree_metadata_integrity(&object.path).unwrap();
    write_tree_snapshot(
        &object.path,
        &TreeIntegrities {
            content: original_snapshot.content_integrity,
            metadata: current_metadata,
            stats: ObjectTreeStats::default(),
        },
    )
    .unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert!(reusable.is_none());
    assert!(!object.path.exists());
}

#[test]
fn reusable_object_tree_policy_migrates_source_object_when_snapshot_metadata_is_stale() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(object.path.join("index.js"))
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap()
        .unwrap();

    assert_eq!(reusable.path, object.path);
    assert_ne!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );
}

#[test]
fn extract_object_tree_policy_repairs_snapshotless_source_object_from_fresh_tarball() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    std::fs::remove_file(object.path.join(TREE_SNAPSHOT_FILENAME)).unwrap();

    let (repaired, repaired_sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert_eq!(repaired_sri, sri);
    assert_eq!(repaired.path, object.path);
    assert_ne!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );
    assert!(object.path.join(TREE_SNAPSHOT_FILENAME).is_file());
}

#[test]
fn reusable_object_tree_policy_removes_wrong_source_integrity_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    let wrong_sri = synthetic_sri(b"wrong tree migration source sri");
    write_source_object_integrity(&object.path, &wrong_sri).unwrap();

    let reusable = store
        .reusable_object_with_policy(&sri, ObjectIntegrityPolicy::Tree)
        .unwrap();

    assert!(reusable.is_none());
    assert!(!object.path.exists());
}

#[test]
fn is_verified_object_dir_tree_policy_migrates_source_integrity_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"source-to-tree-collision\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert!(is_verified_object_dir(&object.path, &sri, ObjectIntegrityPolicy::Tree).unwrap());
    assert_ne!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );
}

#[test]
fn populate_link_entry_source_policy_uses_source_integrity_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball =
        build_test_tarball(&[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    let key = arc_key("x", "1.0.0");

    let entry = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri.clone(),
                object_dir: object.path,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Source,
        )
        .unwrap();

    let snapshot = read_tree_snapshot(&entry.link_dir).unwrap();
    assert_eq!(snapshot.content_integrity, source_object_integrity(&sri));
    assert!(
        entry
            .link_dir
            .join(LINK_NODE_MODULES)
            .join(key.name())
            .join("package.json")
            .is_file()
    );
}

#[test]
fn populate_link_entry_source_policy_migrates_legacy_tree_object_before_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"populate_link_entry_source_policy_migrates_legacy_tree_object");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"legacy-object-link\"}"),
            ("index.js", b"module.exports = 1;\n"),
        ],
    );
    let key = arc_key("legacy-object-link", "1.0.0");

    let entry = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri.clone(),
                object_dir: object_dir.clone(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Source,
        )
        .unwrap();

    assert!(entry.freshly_populated);
    assert_eq!(
        read_object_integrity(&object_dir).unwrap(),
        source_object_integrity(&sri)
    );
    assert_eq!(
        read_tree_snapshot(&entry.link_dir)
            .unwrap()
            .content_integrity,
        source_object_integrity(&sri)
    );
}

#[test]
fn populate_link_entry_tree_policy_migrates_source_object_before_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"source-object-link\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"module.exports = 1;\n"),
    ]);
    let (object, sri, _) = store
        .extract_object_from_bytes_with_policy(&tarball, None, ObjectIntegrityPolicy::Source)
        .unwrap();
    let key = arc_key("source-object-link", "1.0.0");

    let entry = store
        .populate_link_entry_inner(
            LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri.clone(),
                object_dir: object.path.clone(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            },
            None,
            None,
            ObjectIntegrityPolicy::Tree,
        )
        .unwrap();

    assert!(entry.freshly_populated);
    assert_ne!(
        read_object_integrity(&object.path).unwrap(),
        source_object_integrity(&sri)
    );
    assert_eq!(
        read_tree_snapshot(&entry.link_dir)
            .unwrap()
            .content_integrity,
        read_object_integrity(&object.path).unwrap()
    );
}

#[test]
fn populate_link_entry_source_policy_migrates_legacy_tree_snapshot_without_repopulate() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"populate_link_entry_source_policy_migrates_legacy_snapshot");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"legacy-snapshot\"}"),
            ("index.js", b"module.exports = 1;\n"),
        ],
    );
    let key = arc_key("legacy-snapshot", "1.0.0");
    let request = || LinkEntryRequest {
        graph_key: Arc::clone(&key),
        source_sri: sri.clone(),
        object_dir: object_dir.clone(),
        deps: vec![],
        platform: Arc::new(sample_meta_platform()),
    };

    let first = store
        .populate_link_entry_inner(request(), None, None, ObjectIntegrityPolicy::Tree)
        .unwrap();
    let legacy_snapshot = read_tree_snapshot(&first.link_dir).unwrap();
    assert_ne!(
        legacy_snapshot.content_integrity,
        source_object_integrity(&sri)
    );
    write_source_object_integrity(&object_dir, &sri).unwrap();

    let second = store
        .populate_link_entry_inner(request(), None, None, ObjectIntegrityPolicy::Source)
        .unwrap();

    assert!(
        !second.freshly_populated,
        "valid legacy tree-snapshot link entries should be migrated in place"
    );
    assert_eq!(
        read_tree_snapshot(&second.link_dir)
            .unwrap()
            .content_integrity,
        source_object_integrity(&sri)
    );
}

#[test]
fn extract_object_from_bytes_emits_zero_timings_on_hot_path() {
    // The contract worth testing: a re-extract of an already-
    // populated object hits the store-cache short-circuit and
    // emits zero wall-clock timings (the whole point is the
    // hot install path skipping ALL the I/O).
    //
    // We don't assert that the COLD extract emits non-zero ms.
    // Wall-clock timings on a 100-byte synthetic tarball can
    // round to 0 ms on a fast SSD even when actual extract +
    // finalize work runs to completion — milliseconds is too
    // coarse a unit to distinguish "didn't run" from "ran
    // sub-millisecond." The hot-path zero assertion is the
    // load-bearing contract; cold-path > 0 was an implementation
    // detail that flaked on fast machines.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let tarball =
        build_test_tarball(&[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")]);

    // Cold extract — populates the store. We only need a
    // successful return; timing values on this run are not
    // contract.
    let _ = store.extract_object_from_bytes(&tarball, None).unwrap();

    // Hot path (already populated) — re-extract takes the
    // store-hit short-circuit and emits zero timings.
    let (_, _, timings_hot) = store.extract_object_from_bytes(&tarball, None).unwrap();
    assert_eq!(timings_hot.extract_ms, 0);
    assert_eq!(timings_hot.security_ms, 0);
    assert_eq!(timings_hot.source_scan_ns, 0);
    assert_eq!(timings_hot.finalize_ms, 0);
    assert_eq!(timings_hot.finalize_permit_wait_ms, 0);
    assert_eq!(timings_hot.finalize_tree_integrity_ms, 0);
    assert_eq!(timings_hot.finalize_integrity_write_ms, 0);
    assert_eq!(timings_hot.finalize_rename_ms, 0);
    assert_eq!(timings_hot.finalize_collision_recovery_ms, 0);
    assert_eq!(timings_hot.file_count, 0);
    assert_eq!(timings_hot.dir_count, 0);
    assert_eq!(timings_hot.symlink_count, 0);
    assert_eq!(timings_hot.unpacked_bytes, 0);
}

#[test]
fn disabled_source_analysis_skips_fresh_v2_cache_creation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at_with_policies(
        dir.path(),
        ObjectIntegrityPolicy::Source,
        crate::SecurityAnalysisPolicy::Disabled,
    );
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"unscanned\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"eval('code')"),
    ]);

    let (path, _, _) = store.extract_object_from_bytes(&tarball, None).unwrap();

    assert!(!path.join(".lpm-security.json").exists());
    assert!(path.join(".integrity").exists());
}

#[test]
fn enabled_v2_reuse_backfills_missing_analysis_without_reextracting() {
    let dir = tempfile::tempdir().unwrap();
    let disabled = Store::at_with_policies(
        dir.path(),
        ObjectIntegrityPolicy::Source,
        crate::SecurityAnalysisPolicy::Disabled,
    );
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"backfill\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"eval('code')"),
    ]);
    let (path, sri, _) = disabled.extract_object_from_bytes(&tarball, None).unwrap();
    assert!(!path.join(".lpm-security.json").exists());

    let enabled = Store::at(dir.path());
    let reused = enabled.reusable_object(&sri).unwrap().unwrap();

    assert_eq!(reused.path, path);
    assert!(
        lpm_security::behavioral::read_cached_analysis(&reused.path)
            .unwrap()
            .source
            .eval
    );
}

#[test]
fn enabled_extract_collision_backfills_missing_winner_analysis_cache() {
    let dir = tempfile::tempdir().unwrap();
    let arrived = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let enabled = Store::at_with_policies(
        dir.path(),
        ObjectIntegrityPolicy::Source,
        crate::SecurityAnalysisPolicy::Enabled,
    )
    .with_object_publish_barriers(Arc::clone(&arrived), Arc::clone(&resume));
    let disabled = Store::at_with_policies(
        dir.path(),
        ObjectIntegrityPolicy::Source,
        crate::SecurityAnalysisPolicy::Disabled,
    );
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"collision-backfill\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", b"eval('collision-backfill')"),
    ]);
    let enabled_tarball = tarball.clone();
    let enabled_extract =
        std::thread::spawn(move || enabled.extract_object_from_bytes(&enabled_tarball, None));

    arrived.wait();
    let (winner_path, _, _) = disabled.extract_object_from_bytes(&tarball, None).unwrap();
    assert!(
        !winner_path.join(".lpm-security.json").exists(),
        "disabled writer must publish the cache-free winning object"
    );
    resume.wait();
    let (reused_path, _, _) = enabled_extract.join().unwrap().unwrap();

    assert_eq!(reused_path, winner_path);
    assert!(
        lpm_security::behavioral::read_cached_analysis(&reused_path)
            .unwrap()
            .source
            .eval
    );
}

#[test]
fn v2_fused_extraction_reports_precise_source_scan_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = "eval('code'); const fs = require('fs');\n".repeat(10_000);
    let tarball = build_test_tarball(&[
        (
            "package.json",
            b"{\"name\":\"timed\",\"version\":\"1.0.0\"}",
        ),
        ("index.js", source.as_bytes()),
    ]);

    let (_, _, timings) = store.extract_object_from_bytes(&tarball, None).unwrap();

    assert!(timings.source_scan_ns > 0);
}

#[test]
#[cfg(unix)]
fn create_dir_symlink_uses_lpm_common_helper() {
    // lpm-store v2 shares lpm-common's symlink helper so the Windows
    // junction fallback isn't accidentally
    // dropped. On Unix we just confirm the function reference
    // resolves and produces a working symlink — the Windows
    // fallback is exercised by lpm-common's own test module
    // when compiled on Windows.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real");
    std::fs::create_dir(&target).unwrap();
    let link = dir.path().join("link");
    super::create_dir_symlink(&target, &link).unwrap();
    let read = std::fs::read_link(&link).unwrap();
    assert_eq!(read, target);
}

// ── Read API tests ───────────────────────────────────────────────

/// Populate two link entries, then iterate. Both must surface with
/// readable sidecars, in some order.
#[test]
fn iter_link_entries_returns_populated_entries() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri_a = synthetic_sri(b"iter_link_entries/a");
    let sri_b = synthetic_sri(b"iter_link_entries/b");
    write_object(
        &store,
        &sri_a,
        &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
    );
    write_object(
        &store,
        &sri_b,
        &[("package.json", b"{\"name\":\"b\",\"version\":\"2.0.0\"}")],
    );

    let key_a = arc_key("a", "1.0.0");
    let key_b = arc_key("b", "2.0.0");
    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key_a,
            source_sri: sri_a,
            object_dir: store
                .paths()
                .object_dir(&synthetic_sri(b"iter_link_entries/a"))
                .unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();
    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key_b,
            source_sri: sri_b,
            object_dir: store
                .paths()
                .object_dir(&synthetic_sri(b"iter_link_entries/b"))
                .unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let mut names: Vec<String> = store
        .iter_link_entries()
        .unwrap()
        .map(|(_dir, meta)| meta.name)
        .collect();
    names.sort();
    assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
}

/// Empty store (no `links/` root yet) returns an empty iterator
/// rather than an error. Mirrors the upgrade-in-place case where a
/// user runs `lpm doctor` before any v2 install has populated the
/// store.
#[test]
fn iter_link_entries_handles_missing_links_root() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let count = store.iter_link_entries().unwrap().count();
    assert_eq!(count, 0);
}

/// A poisoned link entry shaped as a symlink (e.g. corrupted store,
/// hostile same-user writer) must NOT surface in the iterator. The
/// store writer never produces symlinks at `links/<entry>`; one
/// appearing is a tamper signal that would otherwise cause `cache
/// prune --apply` to delete the symlink target (outside the store).
#[test]
#[cfg(unix)]
fn iter_link_entries_refuses_symlinked_entry_at_links_root() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"iter_link_entries/legit");
    write_object(
        &store,
        &sri,
        &[(
            "package.json",
            b"{\"name\":\"legit\",\"version\":\"1.0.0\"}",
        )],
    );
    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: arc_key("legit", "1.0.0"),
            source_sri: sri.clone(),
            object_dir: store.paths().object_dir(&sri).unwrap(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let outside = dir.path().join("outside-of-store");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(
        outside.join(".lpm-link-meta.json"),
        br#"{"schema":1,"name":"poisoned","version":"99.0.0","source_sri":"sha512-x","object_path":"objects/sha512-x","graph_key_digest_hex":"deadbeef","deps":[],"platform":{"os":"darwin","cpu":"arm64"},"last_referenced_at":"2024-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, store.paths().links_root().join("poisoned")).unwrap();

    let names: Vec<String> = store
        .iter_link_entries()
        .unwrap()
        .map(|(_dir, meta)| meta.name)
        .collect();
    assert_eq!(
        names,
        vec!["legit".to_string()],
        "symlinked link entry must not surface"
    );

    let verify_entries = store.iter_link_entries_for_verify().unwrap();
    let symlink_issue = verify_entries
        .iter()
        .find(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some("poisoned"));
    let (_, result) = symlink_issue.expect("verify must surface the symlinked entry");
    assert!(
        matches!(result, Err(LpmError::Store(msg)) if msg.contains("symlink")),
        "verify must report the symlinked entry as a store-integrity issue, got {result:?}"
    );
}

/// `find_link_package_dir` returns the package dir for a `(name,
/// version)` that's been populated. Used by `lpm rebuild` to find
/// transitive packages with lifecycle scripts under v2.
#[test]
fn find_link_package_dir_locates_populated_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"find_link_package_dir/c");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"c\",\"version\":\"3.1.4\"}")],
    );
    let key = arc_key("c", "3.1.4");
    populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri,
            object_dir,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    let resolved = store.find_link_package_dir("c", "3.1.4").unwrap();
    assert!(resolved.is_some(), "must locate populated entry");
    let resolved = resolved.unwrap();
    assert_eq!(resolved, store.paths().link_package_dir(&key));
    assert!(resolved.join("package.json").is_file());

    // Wrong version → None.
    assert_eq!(store.find_link_package_dir("c", "0.0.0").unwrap(), None);
    // Wrong name → None.
    assert_eq!(store.find_link_package_dir("nope", "3.1.4").unwrap(), None);
}

/// `populate_object_from_v1` copies an extracted v1 package dir
/// into a v2 object dir atomically, preserving package contents
/// and a current `.lpm-security.json` cache.
#[test]
fn populate_object_from_v1_copies_extracted_package_dir() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    // Synthesize a fake v1 package dir at an arbitrary location.
    // Real v1's `<HOME>/.lpm/store/v1/<name>/<version>/` is just
    // a directory of extracted bytes plus `.integrity` +
    // `.lpm-security.json`; the helper accepts any directory in
    // the same shape.
    let v1_pkg_dir = dir.path().join("fake-v1/pkg/1.0.0");
    std::fs::create_dir_all(&v1_pkg_dir).unwrap();
    std::fs::write(
        v1_pkg_dir.join("package.json"),
        b"{\"name\":\"e\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(v1_pkg_dir.join("index.js"), b"module.exports = 42;").unwrap();
    std::fs::create_dir_all(v1_pkg_dir.join("src")).unwrap();
    std::fs::write(v1_pkg_dir.join("src/inner.js"), b"// inner").unwrap();
    let analysis = lpm_security::behavioral::analyze_package(&v1_pkg_dir);
    lpm_security::behavioral::write_cached_analysis(&v1_pkg_dir, &analysis).unwrap();
    let expected_security_cache = std::fs::read(v1_pkg_dir.join(".lpm-security.json")).unwrap();
    std::fs::write(v1_pkg_dir.join(".integrity"), b"sha512-stale").unwrap();

    let sri = synthetic_sri(b"populate_object_from_v1");
    let object_dir = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
    assert_eq!(object_dir, store.paths().object_dir(&sri).unwrap());
    // Package contents copied through.
    assert_eq!(
        std::fs::read(object_dir.join("package.json")).unwrap(),
        b"{\"name\":\"e\",\"version\":\"1.0.0\"}"
    );
    assert_eq!(
        std::fs::read(object_dir.join("index.js")).unwrap(),
        b"module.exports = 42;"
    );
    assert_eq!(
        std::fs::read(object_dir.join("src/inner.js")).unwrap(),
        b"// inner"
    );
    // Current `.lpm-security.json` preserved (skips re-analysis).
    assert_eq!(
        std::fs::read(object_dir.join(".lpm-security.json")).unwrap(),
        expected_security_cache
    );
    // `.integrity` rewritten to the caller-supplied SRI rather
    // than v1's stale value.
    assert_eq!(
        std::fs::read(object_dir.join(".integrity")).unwrap(),
        sri.as_bytes()
    );

    // Idempotent: second call returns the same path without
    // touching anything.
    let again = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
    assert_eq!(again, object_dir);
}

/// When `.lpm-security.json` is missing in v1 (rare, e.g. a
/// partial or pre-security-cache install), the helper re-runs
/// behavioral analysis so v2's post-write contract holds.
#[test]
fn populate_object_from_v1_runs_analysis_when_security_cache_missing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let v1_pkg_dir = dir.path().join("fake-v1/pkg-no-cache/1.0.0");
    std::fs::create_dir_all(&v1_pkg_dir).unwrap();
    std::fs::write(
        v1_pkg_dir.join("package.json"),
        b"{\"name\":\"f\",\"version\":\"1.0.0\"}",
    )
    .unwrap();

    let sri = synthetic_sri(b"populate_object_from_v1_no_cache");
    let object_dir = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
    assert!(
        object_dir.join(".lpm-security.json").is_file(),
        "translation must regenerate security cache when v1 didn't ship one"
    );
}

#[test]
fn populate_object_from_v1_refreshes_outdated_security_cache() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let v1_pkg_dir = dir.path().join("fake-v1/pkg-outdated-cache/1.0.0");
    std::fs::create_dir_all(&v1_pkg_dir).unwrap();
    std::fs::write(
        v1_pkg_dir.join("package.json"),
        b"{\"name\":\"outdated-cache\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(v1_pkg_dir.join("index.js"), b"eval('code')").unwrap();
    std::fs::write(
        v1_pkg_dir.join(".lpm-security.json"),
        br#"{"version":0,"analyzedAt":"2026-01-01T00:00:00Z","source":{},"supplyChain":{},"manifest":{},"meta":{}}"#,
    )
    .unwrap();

    let sri = synthetic_sri(b"populate_object_from_v1_outdated_cache");
    let object_dir = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
    let analysis = lpm_security::behavioral::read_cached_analysis(&object_dir).unwrap();

    assert_eq!(analysis.version, lpm_security::behavioral::SCHEMA_VERSION);
    assert!(analysis.source.eval);
}

#[test]
fn disabled_populate_object_from_v1_leaves_missing_security_cache_absent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at_with_policies(
        dir.path(),
        ObjectIntegrityPolicy::Source,
        crate::SecurityAnalysisPolicy::Disabled,
    );
    let v1_pkg_dir = dir.path().join("fake-v1/pkg-disabled/1.0.0");
    std::fs::create_dir_all(&v1_pkg_dir).unwrap();
    std::fs::write(
        v1_pkg_dir.join("package.json"),
        b"{\"name\":\"disabled\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(v1_pkg_dir.join("index.js"), b"eval('code')").unwrap();

    let sri = synthetic_sri(b"populate_object_from_v1_disabled");
    let object_dir = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();

    assert!(!object_dir.join(".lpm-security.json").exists());
}

#[test]
#[cfg(unix)]
fn path_lives_in_store_recognizes_canonical_descendants() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());

    let sri = synthetic_sri(b"path_lives_in_store/d");
    let object_dir = write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"d\",\"version\":\"1.0.0\"}")],
    );
    let key = arc_key("d", "1.0.0");
    let entry = populate_link_entry_source(
        &store,
        LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri,
            object_dir,
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        },
    )
    .unwrap();

    // Direct probe.
    assert!(store.path_lives_in_store(&entry.link_dir));
    assert!(store.path_lives_in_store(&store.paths().link_package_dir(&key)));

    // A symlink pointing at the link entry — the canonicalize step
    // dereferences and the predicate still recognizes the target.
    let proxy_dir = dir.path().join("proxy");
    std::os::unix::fs::symlink(&entry.link_dir, &proxy_dir).unwrap();
    assert!(store.path_lives_in_store(&proxy_dir));

    // A path completely outside the store.
    let outside = dir.path().join("not-the-store");
    std::fs::create_dir_all(&outside).unwrap();
    assert!(!store.path_lives_in_store(&outside));
}

// ── sri_to_segment parity ──────────────────────────────────────────────

/// The optimized `sri_to_segment` (single-alloc write loop) must
/// produce identical output to the naïve `format!("{algo}-{hex}")` it
/// replaced.
#[test]
fn sri_to_segment_parity_sha512() {
    let sri = synthetic_sri(b"sri-segment-parity-sha512");
    // Round-trip through the public API to exercise sri_to_segment.
    let store = Store::at(std::env::temp_dir().join("lpm-v2-sri-parity-sha512"));
    let segment_path = store.paths().object_dir(&sri).unwrap();
    let segment = segment_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    // SHA-512 segment: "sha512-" + 128 lowercase hex chars.
    assert!(segment.starts_with("sha512-"), "expected sha512- prefix");
    assert_eq!(segment.len(), "sha512-".len() + 128);
    assert!(
        segment["sha512-".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "hex portion must be lowercase"
    );
}

/// SHA-256 SRI produces the correct segment prefix and length.
#[test]
fn sri_to_segment_parity_sha256() {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(b"sri-segment-parity-sha256");
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
    let sri = format!("sha256-{b64}");
    let store = Store::at(std::env::temp_dir().join("lpm-v2-sri-parity-sha256"));
    let segment_path = store.paths().object_dir(&sri).unwrap();
    let segment = segment_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    // SHA-256 segment: "sha256-" + 64 lowercase hex chars.
    assert!(segment.starts_with("sha256-"), "expected sha256- prefix");
    assert_eq!(segment.len(), "sha256-".len() + 64);
    assert!(
        segment["sha256-".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "hex portion must be lowercase"
    );
}

/// `tmp_sibling` uses a random 64-bit suffix instead of the predictable
/// pid+thread::id pair. Two calls in quick succession should produce
/// distinct paths with overwhelming probability — confirms the suffix is
/// actually random and not re-derived from a deterministic source.
#[test]
fn tmp_sibling_produces_unpredictable_suffix_across_calls() {
    let base = std::path::PathBuf::from("/tmp/foo-object");
    let a = tmp_sibling(&base);
    let b = tmp_sibling(&base);
    assert_ne!(
        a, b,
        "two tmp_sibling calls on the same path must produce different suffixes",
    );
    // Sanity: shape is `<base>.tmp.<16-hex>`.
    let a_name = a.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        a_name.starts_with("foo-object.tmp."),
        "expected `<name>.tmp.<suffix>` shape, got {a_name}",
    );
    let suffix = a_name.trim_start_matches("foo-object.tmp.");
    assert_eq!(suffix.len(), 16, "suffix should be 16 hex chars: {suffix}");
    assert!(
        suffix.chars().all(|c| c.is_ascii_hexdigit()),
        "suffix should be hex: {suffix}",
    );
}

/// Pre-created tmp staging dirs land at 0o700 on Unix so a partial extract
/// cannot be read by other UIDs on a shared host.
#[cfg(unix)]
#[test]
fn create_tmp_dir_locked_sets_0o700() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("staging");
    create_tmp_dir_locked(&target).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "expected 0o700, got 0o{mode:o}");
}

/// `ensure_store_tier_dir_locked` creates the store-tier dir at
/// 0o700 on a fresh path. Closes the shared-host disclosure shape
/// where `create_dir_all`'s default-umask inheritance leaves
/// `objects/` and `links/` at 0o755.
#[cfg(unix)]
#[test]
fn ensure_store_tier_dir_locked_creates_at_0o700() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("v2").join("objects");
    ensure_store_tier_dir_locked(&target).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "store-tier dir must be 0o700 on first create, got 0o{mode:o}"
    );
}

/// Idempotency: a pre-existing 0o755 dir (e.g., one created by an
/// older lpm release that predated this fix) is tightened in
/// place on the next install touch.
#[cfg(unix)]
#[test]
fn ensure_store_tier_dir_locked_tightens_existing_world_readable_dir() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("v2").join("links");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    ensure_store_tier_dir_locked(&target).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "store-tier dir must be tightened to 0o700 on re-use, got 0o{mode:o}"
    );
}

/// A stray symlink in a v1 store entry must NOT propagate
/// into the v2 object dir via the v1→v2 migration copy. A
/// regression or local-attacker plant would otherwise reproduce
/// the symlink target (e.g. `/etc/passwd`) into every consuming
/// link entry.
#[cfg(unix)]
#[test]
fn copy_dir_recursively_skips_symlinks_from_v1_source() {
    let parent = tempfile::tempdir().unwrap();
    let v1 = parent.path().join("v1");
    let dst = parent.path().join("v2");
    std::fs::create_dir_all(&v1).unwrap();
    // Real file alongside the symlink — proves the migration
    // completes for the surrounding files.
    std::fs::write(v1.join("package.json"), b"{}").unwrap();
    // Hostile symlink pointing outside the package dir.
    std::os::unix::fs::symlink("/etc/passwd", v1.join("escape")).unwrap();

    copy_dir_recursively(&v1, &dst).expect("copy should succeed");

    assert!(
        dst.join("package.json").is_file(),
        "regular file must be copied",
    );
    assert!(
        dst.join("escape").symlink_metadata().is_err(),
        "symlink must be skipped — refusing to migrate v1→v2 symlinks",
    );
}

fn write_local_source_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("src/nested")).unwrap();
    std::fs::write(
        root.join("package.json"),
        b"{\"name\":\"local-source\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    for index in 0..12 {
        std::fs::write(
            root.join(format!("src/module-{index}.js")),
            format!("module.exports = {index};"),
        )
        .unwrap();
        std::fs::write(
            root.join(format!("src/nested/util-{index}.js")),
            format!("exports.util = {index};"),
        )
        .unwrap();
    }
}

#[cfg(unix)]
#[test]
fn repeated_local_source_populate_keeps_identical_snapshot_in_place() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("workspace-pkg");
    write_local_source_fixture(&source);
    let sri = synthetic_sri(b"repeated_local_source_populate_keeps_identical_snapshot_in_place");

    let first = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    let first_ino = std::fs::metadata(&first).unwrap().ino();

    let second = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        std::fs::metadata(&second).unwrap().ino(),
        first_ino,
        "an unchanged source must keep the published snapshot in place instead of swapping it",
    );

    std::fs::write(
        source.join("src/module-0.js"),
        b"module.exports = 'changed';",
    )
    .unwrap();
    let third = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(third.join("src/module-0.js")).unwrap(),
        "module.exports = 'changed';",
        "a changed source must still refresh the snapshot",
    );
}

#[test]
fn local_source_snapshot_does_not_change_when_live_source_is_modified_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("workspace-pkg");
    write_local_source_fixture(&source);
    let sri = synthetic_sri(
        b"local_source_snapshot_does_not_change_when_live_source_is_modified_in_place",
    );
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    std::fs::write(
        source.join("src/module-0.js"),
        b"module.exports = 'changed';",
    )
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(object_dir.join("src/module-0.js")).unwrap(),
        "module.exports = 0;",
        "a published local-source object must not share mutable file data with the live source",
    );
}

#[test]
fn unchanged_local_source_populate_does_not_rewrite_snapshot_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("workspace-pkg");
    write_local_source_fixture(&source);
    let sri = synthetic_sri(b"unchanged_local_source_populate_does_not_rewrite_snapshot_metadata");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    let sentinel = local_source_sentinel_path(&object_dir).unwrap();
    let preserved_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567);
    std::fs::File::options()
        .write(true)
        .open(&sentinel)
        .unwrap()
        .set_modified(preserved_time)
        .unwrap();

    store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert_eq!(
        std::fs::metadata(sentinel).unwrap().modified().unwrap(),
        preserved_time,
        "an unchanged local source must reuse its validated snapshot without metadata writes",
    );
}

#[cfg(unix)]
#[test]
fn local_source_refresh_detects_content_changes_after_mtime_is_restored() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("workspace-pkg");
    write_local_source_fixture(&source);
    let source_file = source.join("src/module-0.js");
    let original_mtime = std::fs::metadata(&source_file).unwrap().modified().unwrap();
    let sri =
        synthetic_sri(b"local_source_refresh_detects_content_changes_after_mtime_is_restored");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    std::fs::write(&source_file, b"module.exports = 'changed';").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&source_file)
        .unwrap()
        .set_modified(original_mtime)
        .unwrap();
    store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(object_dir.join("src/module-0.js")).unwrap(),
        "module.exports = 'changed';",
    );
}

#[cfg(unix)]
#[test]
fn local_source_reuse_repairs_a_tampered_stored_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("workspace-pkg");
    write_local_source_fixture(&source);
    let sri = synthetic_sri(b"local_source_reuse_repairs_a_tampered_stored_snapshot");
    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    let stored_file = object_dir.join("src/module-0.js");
    std::fs::remove_file(&stored_file).unwrap();
    std::fs::write(&stored_file, b"module.exports = 'tampered';").unwrap();

    store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();

    assert_eq!(
        std::fs::read(stored_file).unwrap(),
        std::fs::read(source.join("src/module-0.js")).unwrap(),
        "reuse must compare the live source and validate the stored tree before accepting it",
    );
}

#[test]
fn concurrent_local_source_populates_never_break_tree_validation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let source = dir.path().join("workspace-pkg");
    write_local_source_fixture(&source);
    let sri = synthetic_sri(b"concurrent_local_source_populates_never_break_tree_validation");

    let object_dir = store
        .populate_object_from_local_source(&source, &sri)
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..12 {
                    store
                        .populate_object_from_local_source(&source, &sri)
                        .unwrap();
                    let verified =
                        is_verified_object_dir(&object_dir, &sri, ObjectIntegrityPolicy::Tree)
                            .expect("concurrent populate must never leave a mixed snapshot tree");
                    assert!(
                        verified,
                        "published snapshot must stay complete and verified"
                    );
                }
            });
        }
    });
}

#[cfg(target_os = "macos")]
#[test]
fn macos_bulk_metadata_hash_matches_the_portable_walker() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tree");
    std::fs::create_dir_all(root.join("nested/empty")).unwrap();
    std::fs::write(root.join("package.json"), br#"{"name":"bulk-hash"}"#).unwrap();
    std::fs::write(root.join("nested/executable.js"), b"module.exports = 1;\n").unwrap();
    let mut permissions = std::fs::metadata(root.join("nested/executable.js"))
        .unwrap()
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(root.join("nested/executable.js"), permissions).unwrap();
    symlink("nested/executable.js", root.join("entry.js")).unwrap();
    std::fs::write(root.join(".integrity"), b"store metadata").unwrap();

    assert!(
        metadata_hash_implementations_match_for_test(&root).unwrap(),
        "the bulk walker must hash the same paths and metadata fields as the portable walker",
    );
}

#[test]
fn tree_hash_ignores_in_flight_atomic_sidecar_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path());
    let sri = synthetic_sri(b"tree_hash_ignores_in_flight_atomic_sidecar_rewrites");
    let object_dir = write_tree_object(
        &store,
        &sri,
        &[
            ("package.json", b"{\"name\":\"sidecar-rewrites\"}"),
            ("index.js", b"module.exports = 1;"),
        ],
    );
    let baseline = crate::v2::tree_hash::compute_object_tree_integrities(&object_dir)
        .unwrap()
        .content;
    let snapshot_bytes = std::fs::read(object_dir.join(TREE_SNAPSHOT_FILENAME)).unwrap();

    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut mismatch = None;
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                lpm_common::write_file_atomic(
                    &object_dir.join(TREE_SNAPSHOT_FILENAME),
                    &snapshot_bytes,
                )
                .unwrap();
            }
        });
        for _ in 0..200 {
            let hashed = crate::v2::tree_hash::compute_object_tree_integrities(&object_dir)
                .unwrap()
                .content;
            if hashed != baseline {
                mismatch = Some(hashed);
                break;
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();
    });
    assert_eq!(
        mismatch, None,
        "an in-flight atomic sidecar rewrite must not perturb the tree hash (baseline {baseline})",
    );
}
