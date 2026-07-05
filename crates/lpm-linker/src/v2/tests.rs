use super::*;
use crate::LinkDependency;
#[cfg(target_os = "macos")]
use lpm_store::v2::COMPAT_ISLAND_COMPLETE_FILENAME;
use lpm_store::v2::Store as V2Store;
use std::path::PathBuf;

fn synthetic_sri(seed: &[u8]) -> String {
    lpm_store::compute_sri_hash(seed)
}

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

fn write_object(store: &V2Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let tarball = build_test_tarball(files);
    store.extract_object(sri, &tarball).unwrap()
}

#[cfg(unix)]
fn assert_unix_shim_executes_under(shim: &Path, root: &Path, label: &str) {
    let metadata = shim.symlink_metadata().expect("shim metadata");
    if metadata.file_type().is_symlink() {
        let shim_target = std::fs::read_link(shim).expect("shim should be a symlink");
        let shim_real = shim
            .parent()
            .unwrap()
            .join(shim_target)
            .canonicalize()
            .expect("shim target should resolve");
        assert!(
            shim_real.starts_with(root),
            "{label} should execute inside {}, got {}",
            root.display(),
            shim_real.display(),
        );
        return;
    }

    assert!(
        metadata.file_type().is_file(),
        "{label} shim must be a file or symlink"
    );
    let content = std::fs::read_to_string(shim).expect("shim wrapper should be readable");
    let root_text = root.to_string_lossy();
    let root_without_private = root_text.strip_prefix("/private").unwrap_or(&root_text);
    assert!(
        content.contains(root_text.as_ref()) || content.contains(root_without_private),
        "{label} wrapper should execute inside {}, got:\n{content}",
        root.display(),
    );
}

#[cfg(unix)]
fn write_local_source_object(store: &V2Store, sri: &str, source_dir: &Path) -> PathBuf {
    store
        .populate_object_from_local_source(source_dir, sri)
        .unwrap()
}

fn target(name: &str, version: &str, sri: &str, is_direct: bool) -> V2Target {
    V2Target {
        target: LinkTarget {
            name: name.into(),
            version: version.into(),
            store_path: PathBuf::new(), // unused under v2
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            is_direct,
            root_link_names: None,
            wrapper_id: None,
            materialization: crate::Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        },
        source_sri: sri.into(),
        verified_object_integrity: None,
        fresh_object: None,
    }
}

#[cfg(target_os = "macos")]
fn write_tool_source(source_dir: &Path, version: &str, body: &str) {
    std::fs::create_dir_all(source_dir).unwrap();
    std::fs::write(
        source_dir.join("package.json"),
        format!(r#"{{"name":"tool","version":"{version}","bin":{{"tool":"cli.js"}}}}"#),
    )
    .unwrap();
    let cli = source_dir.join("cli.js");
    if cli.exists() {
        std::fs::remove_file(&cli).unwrap();
    }
    std::fs::write(cli, body).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn store_cached_compat_island_refreshes_when_local_source_bytes_change() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let source = tmp.path().join("source-tool");
    let source_sri = synthetic_sri(b"stable-local-tool-source");
    let compat_bins = vec!["tool".to_string()];

    write_tool_source(&source, "1.0.0", "module.exports = 'v1';\n");
    write_local_source_object(&store, &source_sri, &source);
    let first_project = tmp.path().join("project-one");
    std::fs::create_dir_all(&first_project).unwrap();
    link_packages_v2_with_compatibility_bin_names(
        &first_project,
        vec![target("tool", "1.0.0", &source_sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
        &compat_bins,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(first_project.join("node_modules/tool/cli.js")).unwrap(),
        "module.exports = 'v1';\n"
    );

    write_tool_source(&source, "1.0.0", "module.exports = 'v2';\n");
    write_local_source_object(&store, &source_sri, &source);
    let second_project = tmp.path().join("project-two");
    std::fs::create_dir_all(&second_project).unwrap();
    link_packages_v2_with_compatibility_bin_names(
        &second_project,
        vec![target("tool", "1.0.0", &source_sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
        &compat_bins,
    )
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(second_project.join("node_modules/tool/cli.js")).unwrap(),
        "module.exports = 'v2';\n",
        "compat island cache must not reuse bytes from a prior local-source snapshot"
    );
    let compat_count = std::fs::read_dir(store.paths().compat_root())
        .unwrap()
        .filter(|entry| entry.as_ref().is_ok_and(|entry| entry.path().is_dir()))
        .count();
    assert_eq!(
        compat_count, 2,
        "changed local-source bytes should produce a distinct cached island"
    );
}

#[cfg(all(target_os = "macos", unix))]
#[test]
fn store_cached_compat_root_and_island_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let compat_root = store.paths().compat_root().to_path_buf();
    std::fs::create_dir_all(&compat_root).unwrap();
    std::fs::set_permissions(&compat_root, std::fs::Permissions::from_mode(0o755)).unwrap();

    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let sri = synthetic_sri(b"store_cached_compat_root_and_island_are_owner_only");
    write_object(
        &store,
        &sri,
        &[(
            "package.json",
            br#"{"name":"tool","version":"1.0.0","bin":{"tool":"cli.js"}}"#,
        )],
    );
    link_packages_v2_with_compatibility_bin_names(
        &project,
        vec![target("tool", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();

    let root_mode = std::fs::metadata(&compat_root)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(root_mode, 0o700, "compat root mode was 0o{root_mode:o}");
    let island = std::fs::read_dir(&compat_root)
        .unwrap()
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then_some(path)
        })
        .expect("cached island should exist");
    let island_mode = std::fs::metadata(&island).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        island_mode, 0o700,
        "cached island mode was 0o{island_mode:o}"
    );
}

#[test]
fn link_packages_v2_writes_project_root_symlink_for_direct_dep() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"link_packages_v2/single_dep");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
    );

    let result = link_packages_v2(
        &project,
        vec![target("a", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(result.linked, 1);
    assert_eq!(result.symlinked, 1);
    let link = project.join("node_modules").join("a");
    assert!(
        link.symlink_metadata().unwrap().file_type().is_symlink(),
        "root symlink must be a symlink"
    );
    // Resolves to the package dir inside the link entry.
    assert!(link.join("package.json").is_file());
}

#[test]
fn link_packages_v2_resolves_dep_via_key_map() {
    // Two-package install: consumer depends on lib. The lib's
    // graph key must be reachable when populating consumer's
    // sibling-symlinks.
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let lib_sri = synthetic_sri(b"link_packages_v2/lib");
    write_object(
        &store,
        &lib_sri,
        &[("package.json", b"{\"name\":\"lib\",\"version\":\"1.2.3\"}")],
    );
    let cons_sri = synthetic_sri(b"link_packages_v2/consumer");
    write_object(
        &store,
        &cons_sri,
        &[(
            "package.json",
            b"{\"name\":\"consumer\",\"version\":\"0.1.0\",\"dependencies\":{\"lib\":\"1.2.3\"}}",
        )],
    );

    let mut consumer = target("consumer", "0.1.0", &cons_sri, true);
    consumer.target.dependencies = vec![LinkDependency::registry("lib", "1.2.3")];
    let lib = target("lib", "1.2.3", &lib_sri, false);

    let result = link_packages_v2(
        &project,
        vec![consumer, lib],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(result.linked, 2);
    // Only `consumer` is direct → exactly one root symlink.
    assert_eq!(result.symlinked, 1);

    let consumer_root = project.join("node_modules").join("consumer");
    assert!(
        consumer_root
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // Sibling symlink lives at `<consumer_link_dir>/node_modules/lib`,
    // not nested inside `consumer/`. From the project, the
    // sibling is reachable via `<consumer_root>/../lib` once
    // Node resolves the symlink — but the v2 contract is that
    // siblings are wrapper-level, so we walk one parent up.
    let consumer_link_pkg = result
        .materialized
        .iter()
        .find(|m| m.name == "consumer")
        .map(|m| m.destination.clone())
        .unwrap();
    let consumer_link_dir = consumer_link_pkg.parent().unwrap().parent().unwrap();
    let lib_sibling = consumer_link_dir.join("node_modules").join("lib");
    assert!(
        lib_sibling
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "sibling lib must be a symlink alongside consumer in the same node_modules/"
    );
    // And the symlink target resolves to the lib link entry's
    // package.json.
    assert!(lib_sibling.join("package.json").is_file());
}

#[test]
fn link_packages_v2_nests_same_name_dependency_inside_package_node_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let current_sri = synthetic_sri(b"link_packages_v2/same-name/current");
    write_object(
            &store,
            &current_sri,
            &[(
                "package.json",
                br#"{"name":"pangea-lib","version":"4.0.521","dependencies":{"pangea-lib":"2.12.192"}}"#,
            )],
        );
    let legacy_sri = synthetic_sri(b"link_packages_v2/same-name/legacy");
    write_object(
        &store,
        &legacy_sri,
        &[(
            "package.json",
            br#"{"name":"pangea-lib","version":"2.12.192"}"#,
        )],
    );

    let mut current = target("pangea-lib", "4.0.521", &current_sri, true);
    current.target.dependencies = vec![LinkDependency::registry("pangea-lib", "2.12.192")];
    let legacy = target("pangea-lib", "2.12.192", &legacy_sri, false);

    let result = link_packages_v2(
        &project,
        vec![current, legacy],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    let current_dir = result
        .materialized
        .iter()
        .find(|pkg| pkg.name == "pangea-lib" && pkg.version == "4.0.521")
        .map(|pkg| pkg.destination.clone())
        .expect("pangea-lib@4 should materialize");
    let nested_legacy = current_dir.join("node_modules").join("pangea-lib");
    assert!(
        nested_legacy
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "same-name dependency must be nested under the package's own node_modules"
    );
    let legacy_manifest = std::fs::read_to_string(nested_legacy.join("package.json")).unwrap();
    assert!(legacy_manifest.contains("2.12.192"));
}

#[test]
fn link_packages_v2_materializes_next_compatibility_island_under_node_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let next_sri = synthetic_sri(b"v2/next-compat/next");
    write_object(
            &store,
            &next_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"next","version":"16.2.4","bin":{"next":"dist/bin/next"},"dependencies":{"@swc/helpers":"0.5.0"},"peerDependencies":{"react":"^19.0.0","react-dom":"^19.0.0"}}"#,
                ),
                ("dist/bin/next", b"#!/usr/bin/env node\n"),
            ],
        );
    let react_sri = synthetic_sri(b"v2/next-compat/react");
    write_object(
        &store,
        &react_sri,
        &[("package.json", br#"{"name":"react","version":"19.2.5"}"#)],
    );
    let react_dom_sri = synthetic_sri(b"v2/next-compat/react-dom");
    write_object(
        &store,
        &react_dom_sri,
        &[(
            "package.json",
            br#"{"name":"react-dom","version":"19.2.5"}"#,
        )],
    );
    let helpers_sri = synthetic_sri(b"v2/next-compat/swc-helpers");
    write_object(
        &store,
        &helpers_sri,
        &[(
            "package.json",
            br#"{"name":"@swc/helpers","version":"0.5.0"}"#,
        )],
    );

    let mut next = target("next", "16.2.4", &next_sri, true);
    next.target.dependencies = vec![LinkDependency::registry("@swc/helpers", "0.5.0")];
    next.target.peers = vec![
        ("react".to_string(), "19.2.5".to_string()),
        ("react-dom".to_string(), "19.2.5".to_string()),
    ];
    let react = target("react", "19.2.5", &react_sri, true);
    let react_dom = target("react-dom", "19.2.5", &react_dom_sri, true);
    let helpers = target("@swc/helpers", "0.5.0", &helpers_sri, false);

    let result = link_packages_v2_with_compatibility_bin_names(
        &project,
        vec![next, react, react_dom, helpers],
        &store,
        LinkerMode::Isolated,
        None,
        &["next".to_string()],
    )
    .unwrap();

    assert_eq!(result.bin_linked, 1, "next's bin shim must still be linked");
    let compat_root = project
        .join("node_modules")
        .join(".lpm")
        .join("compat")
        .canonicalize()
        .expect("compatibility root should exist");
    assert!(
        !project.join(".lpm").join("compat").exists(),
        "compatibility layout must not sit at project root where framework watchers recurse",
    );
    let store_root = store
        .paths()
        .root()
        .canonicalize()
        .expect("store root should exist");
    let next_root = project.join("node_modules").join("next");
    let next_real = next_root
        .canonicalize()
        .expect("project next root should resolve");
    assert!(
        next_real.starts_with(&compat_root),
        "Next's root realpath must stay under the project compatibility island, got {}",
        next_real.display(),
    );
    assert!(
        !next_real.starts_with(&store_root),
        "Next's root realpath must not point straight into the global v2 store",
    );

    let compat_node_modules = next_real
        .parent()
        .expect("next package dir should live under node_modules");
    for package in ["react", "react-dom", "@swc/helpers"] {
        let package_dir = compat_node_modules.join(package);
        assert!(
            package_dir.join("package.json").is_file(),
            "{package} must be available inside Next's project-local compatibility island",
        );
        let package_real = package_dir
            .canonicalize()
            .unwrap_or_else(|e| panic!("{package} should resolve: {e}"));
        assert!(
            package_real.starts_with(&compat_root),
            "{package} must resolve inside the project compatibility island, got {}",
            package_real.display(),
        );
        assert!(
            !package_real.starts_with(&store_root),
            "{package} must not resolve straight into the global v2 store",
        );
    }

    #[cfg(unix)]
    {
        let shim = project.join("node_modules").join(".bin").join("next");
        assert_unix_shim_executes_under(&shim, &compat_root, "next bin shim");
    }
}

/// The macOS store-cache path must: (1) publish the island once in the
/// global store keyed by its entry set, (2) reproduce it in the project
/// with position-independent (relative) internal symlinks, and (3) on a
/// `node_modules`-removed warm relink, reuse the cached store island
/// rather than rebuilding it — the whole point of the cache.
#[cfg(target_os = "macos")]
#[test]
fn store_cached_compat_island_is_reused_across_node_modules_removal() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let tool_sri = synthetic_sri(b"v2/store-cache/tool");
    write_object(
            &store,
            &tool_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"},"dependencies":{"helper":"1.0.0"}}"#,
                ),
                ("bin/tool.js", b"#!/usr/bin/env node\n"),
            ],
        );
    let helper_sri = synthetic_sri(b"v2/store-cache/helper");
    write_object(
        &store,
        &helper_sri,
        &[("package.json", br#"{"name":"helper","version":"1.0.0"}"#)],
    );

    let make_targets = || {
        let mut tool = target("tool", "1.0.0", &tool_sri, true);
        tool.target.dependencies = vec![LinkDependency::registry("helper", "1.0.0")];
        vec![tool, target("helper", "1.0.0", &helper_sri, false)]
    };

    link_packages_v2_with_compatibility_bin_names(
        &project,
        make_targets(),
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();

    // (1) Exactly one cached island, published with its completion sentinel.
    let compat_store_root = store.paths().compat_root();
    let islands: Vec<_> = std::fs::read_dir(compat_store_root)
        .expect("store compat root should exist")
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(islands.len(), 1, "exactly one cached island expected");
    let island_dir = islands[0].path();
    assert!(
        island_dir.join(COMPAT_ISLAND_COMPLETE_FILENAME).is_file(),
        "store island must carry its completion sentinel",
    );

    // (2) The project island's sibling edge must be a RELATIVE symlink so
    // the whole-island clone stays valid at its destination.
    let sibling = find_symlink_named(&project.join("node_modules/.lpm/compat"), "helper")
        .expect("helper sibling symlink should exist in the project island");
    let target_path = std::fs::read_link(&sibling).unwrap();
    assert!(
        target_path.is_relative(),
        "island sibling symlink must be relative, got {}",
        target_path.display(),
    );
    assert!(sibling.exists(), "relative sibling symlink must resolve");

    // (3) Warm relink after node_modules removal must REUSE the cached
    // island, not rebuild it. Drop a probe file into the store island; a
    // rebuild publishes via atomic tmp→rename and would lose it, whereas
    // reuse leaves the island dir untouched (only its sentinel mtime is
    // refreshed for LRU).
    let probe = island_dir.join(".reuse-probe");
    std::fs::write(&probe, b"x").unwrap();
    std::fs::remove_dir_all(project.join("node_modules")).unwrap();

    link_packages_v2_with_compatibility_bin_names(
        &project,
        make_targets(),
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();

    let still_one = std::fs::read_dir(compat_store_root)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .count();
    assert_eq!(still_one, 1, "warm relink must not create a second island");
    assert!(
        probe.exists(),
        "warm relink must reuse the cached store island, not rebuild it",
    );
    assert!(
        find_symlink_named(&project.join("node_modules/.lpm/compat"), "helper")
            .is_some_and(|p| p.exists()),
        "project island must be reproduced after node_modules removal",
    );
}

/// Recursively find the first symlink whose file name matches `name`.
#[cfg(target_os = "macos")]
fn find_symlink_named(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ft = entry.file_type().ok()?;
        if ft.is_symlink() {
            if entry.file_name().to_str() == Some(name) {
                return Some(path);
            }
        } else if ft.is_dir()
            && let Some(found) = find_symlink_named(&path, name)
        {
            return Some(found);
        }
    }
    None
}

#[test]
fn link_packages_v2_compatibility_island_prefers_declared_dependency_context() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let server_sri = synthetic_sri(b"v2/compat-context/dev-server");
    write_object(
            &store,
            &server_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"dev-server","version":"1.0.0","bin":{"dev-server":"bin/dev-server.js"},"dependencies":{"shared":"1.0.0"}}"#,
                ),
                ("bin/dev-server.js", b"#!/usr/bin/env node\n"),
            ],
        );
    let cli_sri = synthetic_sri(b"v2/compat-context/delegated-cli");
    write_object(
        &store,
        &cli_sri,
        &[(
            "package.json",
            br#"{"name":"delegated-cli","version":"1.0.0"}"#,
        )],
    );
    let shared_dep_sri = synthetic_sri(b"v2/compat-context/shared-1");
    write_object(
        &store,
        &shared_dep_sri,
        &[("package.json", br#"{"name":"shared","version":"1.0.0"}"#)],
    );
    let shared_root_sri = synthetic_sri(b"v2/compat-context/shared-2");
    write_object(
        &store,
        &shared_root_sri,
        &[("package.json", br#"{"name":"shared","version":"2.0.0"}"#)],
    );

    let mut server = target("dev-server", "1.0.0", &server_sri, true);
    server.target.dependencies = vec![LinkDependency::registry("shared", "1.0.0")];
    let delegated_cli = target("delegated-cli", "1.0.0", &cli_sri, true);
    let shared_dep = target("shared", "1.0.0", &shared_dep_sri, false);
    let shared_root = target("shared", "2.0.0", &shared_root_sri, true);

    link_packages_v2_with_compatibility_bin_names(
        &project,
        vec![server, delegated_cli, shared_dep, shared_root],
        &store,
        LinkerMode::Isolated,
        None,
        &["dev-server".to_string()],
    )
    .unwrap();

    let compat_root = project
        .join("node_modules")
        .join(".lpm")
        .join("compat")
        .canonicalize()
        .expect("compatibility root should exist");
    let server_real = project
        .join("node_modules")
        .join("dev-server")
        .canonicalize()
        .expect("dev-server root should resolve");
    assert!(
        server_real.starts_with(&compat_root),
        "dev-server root should resolve inside compat, got {}",
        server_real.display(),
    );
    let compat_node_modules = server_real
        .parent()
        .expect("dev-server package dir should live under node_modules");

    let shared_package_json = compat_node_modules.join("shared").join("package.json");
    let shared_manifest =
        std::fs::read_to_string(&shared_package_json).expect("shared package.json");
    assert!(
        shared_manifest.contains("\"version\":\"1.0.0\""),
        "package-owned dependency should beat project direct context at {}, got {shared_manifest}",
        shared_package_json.display(),
    );
}

#[test]
fn link_packages_v2_skips_compatibility_for_dependency_free_direct_bin() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/dependency-free-bin/tool");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
            ),
            ("bin/tool.js", b"#!/usr/bin/env node\n"),
        ],
    );

    let result = link_packages_v2(
        &project,
        vec![target("tool", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(result.bin_linked, 1, "tool's bin shim must be linked");
    assert!(
        !project
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .exists(),
        "dependency-free direct bins should not need compatibility islands"
    );
    assert!(
        project
            .join("node_modules")
            .join(".bin")
            .join("tool")
            .exists()
    );
}

#[test]
fn plain_install_links_bins_but_skips_compat_island() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let tool_sri = synthetic_sri(b"v2/plain-install/tool");
    write_object(
            &store,
            &tool_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"},"dependencies":{"helper":"1.0.0"}}"#,
                ),
                ("bin/tool.js", b"#!/usr/bin/env node\n"),
            ],
        );
    let helper_sri = synthetic_sri(b"v2/plain-install/helper");
    write_object(
        &store,
        &helper_sri,
        &[("package.json", br#"{"name":"helper","version":"1.0.0"}"#)],
    );

    let mut tool = target("tool", "1.0.0", &tool_sri, true);
    tool.target.dependencies = vec![LinkDependency::registry("helper", "1.0.0")];

    let result = link_packages_v2(
        &project,
        vec![tool, target("helper", "1.0.0", &helper_sri, false)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(
        result.bin_linked, 1,
        "bin shims must still be linked on a plain install"
    );
    #[cfg(windows)]
    let shim = project.join("node_modules").join(".bin").join("tool.cmd");
    #[cfg(not(windows))]
    let shim = project.join("node_modules").join(".bin").join("tool");
    assert!(
        shim.exists(),
        "tool's bin shim must exist after a plain install",
    );
    #[cfg(unix)]
    {
        let shim_content = std::fs::read_to_string(&shim).expect("tool shim");
        assert!(
            shim_content.contains("NODE_PATH="),
            "dependency-bearing bin should get project NODE_PATH wrapper"
        );
    }
    assert!(
        !project
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .exists(),
        "a plain install (no compatibility bins) must NOT build the compat island",
    );
}

#[test]
fn link_packages_v2_materializes_direct_bin_without_unrelated_direct_deps() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let tool_sri = synthetic_sri(b"v2/default-bin/tool");
    write_object(
            &store,
            &tool_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"},"dependencies":{"helper":"1.0.0"}}"#,
                ),
                ("bin/tool.js", b"#!/usr/bin/env node\n"),
            ],
        );
    let helper_sri = synthetic_sri(b"v2/default-bin/helper");
    write_object(
        &store,
        &helper_sri,
        &[("package.json", br#"{"name":"helper","version":"1.0.0"}"#)],
    );
    let library_sri = synthetic_sri(b"v2/default-bin/library");
    write_object(
        &store,
        &library_sri,
        &[("package.json", br#"{"name":"library","version":"1.0.0"}"#)],
    );

    let mut tool = target("tool", "1.0.0", &tool_sri, true);
    tool.target.dependencies = vec![LinkDependency::registry("helper", "1.0.0")];

    let result = link_packages_v2_with_compatibility_bin_names(
        &project,
        vec![
            tool,
            target("helper", "1.0.0", &helper_sri, false),
            target("library", "1.0.0", &library_sri, true),
        ],
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();

    assert_eq!(result.bin_linked, 1, "tool's bin shim must still be linked");
    let compat_root = project
        .join("node_modules")
        .join(".lpm")
        .join("compat")
        .canonicalize()
        .expect("direct bin should create project compatibility layout");
    let copied_unrelated_library =
        std::fs::read_dir(&compat_root)
            .unwrap()
            .flatten()
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("library@1.0.0+"))
            });
    assert!(
        !copied_unrelated_library,
        "unrelated direct packages must not be blindly copied into compatibility islands"
    );
    assert!(
        project
            .join("node_modules")
            .join(".bin")
            .join("tool")
            .exists()
    );
    #[cfg(unix)]
    {
        let shim = project.join("node_modules").join(".bin").join("tool");
        assert_unix_shim_executes_under(&shim, &compat_root, "direct bin shim");
    }
}

#[test]
fn link_packages_v2_with_requested_bin_materializes_project_compatibility_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/unrequested-bin/tool");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
            ),
            ("bin/tool.js", b"#!/usr/bin/env node\n"),
        ],
    );

    let result = link_packages_v2_with_compatibility_bin_names(
        &project,
        vec![target("tool", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();

    assert_eq!(result.bin_linked, 1, "tool's bin shim must be linked");
    let compat_root = project
        .join("node_modules")
        .join(".lpm")
        .join("compat")
        .canonicalize()
        .expect("requested direct bin should create project compatibility layout");
    assert!(compat_root.is_dir());
    #[cfg(unix)]
    {
        let shim = project.join("node_modules").join(".bin").join("tool");
        assert_unix_shim_executes_under(&shim, &compat_root, "requested direct bin shim");
    }
}

#[test]
fn project_compatibility_bins_ready_accepts_projects_without_direct_bins() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let package_dir = project.join("node_modules").join("library");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        br#"{"name":"library","version":"1.0.0"}"#,
    )
    .unwrap();

    assert!(
        project_compatibility_bins_ready(&project, &[]),
        "projects with no direct package bins do not need a compatibility .bin layout"
    );
}

#[test]
fn project_compatibility_bins_ready_rejects_missing_discovered_direct_bin() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let package_dir = project.join("node_modules").join("tool");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
            package_dir.join("package.json"),
            br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"},"dependencies":{"helper":"1.0.0"}}"#,
        )
        .unwrap();

    assert!(
        !project_compatibility_bins_ready(&project, &[]),
        "discovered direct package bins require a .bin shim into the compatibility layout"
    );
}

#[test]
fn project_compatibility_bins_ready_rejects_missing_requested_shim_for_direct_bin() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let package_dir = project.join("node_modules").join("tool");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
    )
    .unwrap();

    assert!(
        !project_compatibility_bins_ready(&project, &["tool".to_string()]),
        "a requested package bin requires a .bin shim into the compatibility layout"
    );
}

#[cfg(unix)]
#[test]
fn finalize_existing_link_entries_refreshes_compatibility_copy_after_generated_bin() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/generated-bin/tool");
    write_object(
        &store,
        &sri,
        &[(
            "package.json",
            br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
        )],
    );
    let tool = target("tool", "1.0.0", &sri, true);

    let first = link_packages_v2_with_compatibility_bin_names(
        &project,
        vec![tool.clone()],
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();
    assert_eq!(
        first.bin_linked, 0,
        "pre-build link must skip a declared bin whose target does not exist yet"
    );

    let link_pkg = store
        .find_link_package_dir("tool", "1.0.0")
        .unwrap()
        .expect("initial link must populate the v2 link entry");
    let generated_bin = link_pkg.join("bin").join("tool.js");
    std::fs::create_dir_all(generated_bin.parent().unwrap()).unwrap();
    std::fs::write(&generated_bin, b"#!/usr/bin/env node\n").unwrap();

    let refreshed = finalize_existing_link_entries_with_compatibility_bin_names(
        &project,
        vec![tool],
        &store,
        LinkerMode::Isolated,
        None,
        &["tool".to_string()],
    )
    .unwrap();
    assert_eq!(
        refreshed.bin_linked, 1,
        "post-build finalize must link the generated bin"
    );

    let compat_root = project
        .join("node_modules")
        .join(".lpm")
        .join("compat")
        .canonicalize()
        .expect("compatibility root should exist");
    let shim = project.join("node_modules").join(".bin").join("tool");
    assert_unix_shim_executes_under(&shim, &compat_root, "generated bin shim");
}

#[test]
fn link_packages_v2_skips_dependency_local_name_with_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let consumer_sri = synthetic_sri(b"link_packages_v2/unsafe_dep_consumer");
    write_object(
        &store,
        &consumer_sri,
        &[(
            "package.json",
            b"{\"name\":\"consumer\",\"version\":\"1.0.0\"}",
        )],
    );
    let dep_sri = synthetic_sri(b"link_packages_v2/unsafe_dep_target");
    write_object(
        &store,
        &dep_sri,
        &[(
            "package.json",
            b"{\"name\":\"debug\",\"version\":\"1.0.0\"}",
        )],
    );

    let mut consumer = target("consumer", "1.0.0", &consumer_sri, true);
    consumer.target.dependencies = vec![LinkDependency::new(
        "../../../../escape",
        "debug",
        "1.0.0",
        None,
    )];
    let debug = target("debug", "1.0.0", &dep_sri, false);

    let result = link_packages_v2(
        &project,
        vec![consumer, debug],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(result.linked, 2);
    assert!(
        project.join("escape").symlink_metadata().is_err(),
        "unsafe dependency local name must not create an entry outside the link entry",
    );
}

#[cfg(unix)]
#[test]
fn link_packages_v2_supports_local_source_dep_edges() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    let source_dir = tmp.path().join("sources").join("cycle-b");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&source_dir).unwrap();

    std::fs::write(
        source_dir.join("package.json"),
        b"{\"name\":\"@smoke/cycle-b\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    std::fs::write(source_dir.join("index.js"), b"module.exports = 'before';\n").unwrap();

    let local_sri = synthetic_sri(b"link_packages_v2/local_source_cycle_b");
    write_local_source_object(&store, &local_sri, &source_dir);

    let consumer_sri = synthetic_sri(b"link_packages_v2/external_reentry");
    write_object(
            &store,
            &consumer_sri,
            &[(
                "package.json",
                b"{\"name\":\"external-reentry\",\"version\":\"1.0.0\",\"dependencies\":{\"@smoke/cycle-b\":\"1.0.0\"}}",
            )],
        );

    let mut consumer = target("external-reentry", "1.0.0", &consumer_sri, true);
    consumer.target.dependencies = vec![LinkDependency::registry("@smoke/cycle-b", "1.0.0")];

    let mut local = target("@smoke/cycle-b", "1.0.0", &local_sri, false);
    local.target.materialization = crate::Materialization::DirectorySource;

    let result = link_packages_v2(
        &project,
        vec![consumer, local],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    let consumer_link_pkg = result
        .materialized
        .iter()
        .find(|m| m.name == "external-reentry")
        .map(|m| m.destination.clone())
        .unwrap();
    let consumer_link_dir = consumer_link_pkg.parent().unwrap().parent().unwrap();
    let local_sibling = consumer_link_dir
        .join("node_modules")
        .join("@smoke/cycle-b");
    assert!(
        local_sibling.join("package.json").is_file(),
        "local-source dep sibling must resolve inside the consumer link entry"
    );

    let local_link_pkg = result
        .materialized
        .iter()
        .find(|m| m.name == "@smoke/cycle-b")
        .map(|m| m.destination.clone())
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(local_link_pkg.join("index.js")).unwrap(),
        "module.exports = 'before';\n"
    );
    assert!(
        !local_link_pkg
            .join("index.js")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "local-source entrypoints must be real files so Node resolves deps from the v2 link entry"
    );
}

#[test]
fn link_packages_v2_wipes_legacy_v1_wrappers() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    let v1_wrappers = project.join(".lpm").join("wrappers").join("stale@1.0.0");
    std::fs::create_dir_all(&v1_wrappers).unwrap();
    std::fs::write(v1_wrappers.join("ghost"), b"left over").unwrap();

    let sri = synthetic_sri(b"link_packages_v2/wipe");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")],
    );

    link_packages_v2(
        &project,
        vec![target("x", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert!(
        !project.join(".lpm").join("wrappers").exists(),
        "v2 linker must wipe legacy v1 wrapper tree"
    );
}

#[test]
fn link_packages_v2_with_explicit_root_link_names() {
    // `root_link_names = Some([])` means "explicitly no root
    // symlinks" — even for an `is_direct = true` target. Mirrors
    // the LinkTarget contract.
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");

    let sri = synthetic_sri(b"link_packages_v2/explicit_empty");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
    );

    let mut t = target("a", "1.0.0", &sri, true);
    t.target.root_link_names = Some(vec![]);
    let result = link_packages_v2(&project, vec![t], &store, LinkerMode::Isolated, None).unwrap();
    assert_eq!(result.symlinked, 0);
    assert!(!project.join("node_modules").join("a").exists());
}

#[test]
fn link_packages_v2_removes_stale_root_symlinks_without_wiping_node_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let a_sri = synthetic_sri(b"v2/reconcile/a");
    let b_sri = synthetic_sri(b"v2/reconcile/b");
    write_object(
        &store,
        &a_sri,
        &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
    );
    write_object(
        &store,
        &b_sri,
        &[("package.json", b"{\"name\":\"b\",\"version\":\"1.0.0\"}")],
    );

    link_packages_v2(
        &project,
        vec![
            target("a", "1.0.0", &a_sri, true),
            target("b", "1.0.0", &b_sri, true),
        ],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();
    assert!(project.join("node_modules").join("a").exists());
    assert!(project.join("node_modules").join("b").exists());

    link_packages_v2(
        &project,
        vec![target("a", "1.0.0", &a_sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert!(project.join("node_modules").join("a").exists());
    assert!(!project.join("node_modules").join("b").exists());
    assert!(project.join("node_modules").exists());
}

#[test]
fn link_packages_v2_self_reference() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"link_packages_v2/self_ref");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"d\",\"version\":\"1.0.0\"}")],
    );

    let result = link_packages_v2(
        &project,
        vec![target("d", "1.0.0", &sri, false)],
        &store,
        LinkerMode::Isolated,
        Some("self-pkg"),
    )
    .unwrap();

    assert!(result.self_referenced);
    let self_link = project.join("node_modules").join("self-pkg");
    let read = std::fs::read_link(&self_link).unwrap();
    assert_eq!(read, project);
}

#[test]
fn link_packages_v2_skips_self_reference_when_project_name_contains_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"link_packages_v2/self_ref_traversal");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"d\",\"version\":\"1.0.0\"}")],
    );

    let result = link_packages_v2(
        &project,
        vec![target("d", "1.0.0", &sri, false)],
        &store,
        LinkerMode::Isolated,
        Some("../escape"),
    )
    .unwrap();

    assert!(
        !result.self_referenced,
        "unsafe self-reference names must be skipped"
    );
    assert!(
        !project.join("escape").exists(),
        "self-reference must not create an entry outside node_modules",
    );
}

#[test]
fn link_packages_v2_missing_dep_key_surfaces_error() {
    // A LinkTarget references a dep version that wasn't included
    // in the install set — must NOT silently produce a broken
    // sibling symlink.
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");

    let sri = synthetic_sri(b"link_packages_v2/missing_dep");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"c\",\"version\":\"1.0.0\"}")],
    );
    let mut t = target("c", "1.0.0", &sri, true);
    // Dep 'phantom@9.9.9' has no matching LinkTarget in the set.
    t.target.dependencies = vec![LinkDependency::registry("phantom", "9.9.9")];

    let err = link_packages_v2(&project, vec![t], &store, LinkerMode::Isolated, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("phantom@9.9.9"),
        "missing-dep error must name the missing edge: {msg}"
    );
}

/// **Cross-project peer-divergence invariant.**
///
/// The same consumer package + edge graph but a different
/// resolved-peer version MUST produce distinct GraphKeys, so two
/// projects that pin the same peer differently get separate
/// `links/<key>/` entries instead of silently sharing.
///
/// Setup: two installs, each with consumer `c@1.0.0` declaring
/// peer `react`. Install 1 has `react@18.0.0` in its install set;
/// install 2 has `react@19.0.0`. Both call `link_packages_v2` and
/// the resulting MaterializedPackage destinations for `c@1.0.0`
/// must differ (because the GraphKey path component differs).
#[test]
fn link_packages_v2_distinct_keys_for_peer_divergent_projects() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));

    let c_pkg_json =
        b"{\"name\":\"c\",\"version\":\"1.0.0\",\"peerDependencies\":{\"react\":\"*\"}}";
    let c_sri = synthetic_sri(b"peer_divergent/c");
    write_object(&store, &c_sri, &[("package.json", c_pkg_json)]);

    let r18_sri = synthetic_sri(b"peer_divergent/react@18");
    write_object(
        &store,
        &r18_sri,
        &[(
            "package.json",
            b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
        )],
    );
    let r19_sri = synthetic_sri(b"peer_divergent/react@19");
    write_object(
        &store,
        &r19_sri,
        &[(
            "package.json",
            b"{\"name\":\"react\",\"version\":\"19.0.0\"}",
        )],
    );

    // Project 1: c + react@18. `LinkTarget.peers` arrives empty
    // here — same shape as the lockfile fast path — so
    // `ensure_peer_context` derives peers by reading c's
    // `package.json` and intersecting with the install set.
    let proj1 = tmp.path().join("project1");
    std::fs::create_dir_all(&proj1).unwrap();
    let result_p1 = link_packages_v2(
        &proj1,
        vec![
            target("c", "1.0.0", &c_sri, true),
            target("react", "18.0.0", &r18_sri, false),
        ],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    // Project 2: c + react@19.
    let proj2 = tmp.path().join("project2");
    std::fs::create_dir_all(&proj2).unwrap();
    let result_p2 = link_packages_v2(
        &proj2,
        vec![
            target("c", "1.0.0", &c_sri, true),
            target("react", "19.0.0", &r19_sri, false),
        ],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    let c_dest_p1 = result_p1
        .materialized
        .iter()
        .find(|m| m.name == "c")
        .map(|m| m.destination.clone())
        .expect("c materialized in project 1");
    let c_dest_p2 = result_p2
        .materialized
        .iter()
        .find(|m| m.name == "c")
        .map(|m| m.destination.clone())
        .expect("c materialized in project 2");
    assert_ne!(
        c_dest_p1, c_dest_p2,
        "peer-divergent installs must produce distinct link entries for c@1.0.0; \
             without peers in the GraphKey they would alias"
    );

    // And each project resolves its peer to the version IT
    // actually has — proj1 sees react@18, proj2 sees react@19.
    // The link entry's sibling symlink targets the version-
    // specific link package dir.
    let r_sibling_p1 = c_dest_p1
        .parent()
        .unwrap()
        .join("react")
        .join("package.json");
    let r_sibling_p2 = c_dest_p2
        .parent()
        .unwrap()
        .join("react")
        .join("package.json");
    let r1_pkg = std::fs::read_to_string(&r_sibling_p1).unwrap();
    let r2_pkg = std::fs::read_to_string(&r_sibling_p2).unwrap();
    assert!(
        r1_pkg.contains("18.0.0"),
        "project 1's c link entry must point at react@18: got {r1_pkg}"
    );
    assert!(
        r2_pkg.contains("19.0.0"),
        "project 2's c link entry must point at react@19: got {r2_pkg}"
    );
}

/// Inverse of the divergence test: same consumer + same resolved
/// peer version across two installs MUST produce the same
/// GraphKey, so the global v2 store can share `links/<key>/`
/// across projects. Without this, every project pays a fresh
/// materialization tax even when the dep + peer graph is
/// identical — defeating the cross-project sharing the v2
/// rewrite is supposed to unlock.
#[test]
fn link_packages_v2_shares_keys_for_peer_identical_projects() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));

    let c_pkg_json =
        b"{\"name\":\"c\",\"version\":\"1.0.0\",\"peerDependencies\":{\"react\":\"*\"}}";
    let c_sri = synthetic_sri(b"peer_shared/c");
    write_object(&store, &c_sri, &[("package.json", c_pkg_json)]);

    let r_sri = synthetic_sri(b"peer_shared/react");
    write_object(
        &store,
        &r_sri,
        &[(
            "package.json",
            b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
        )],
    );

    let proj1 = tmp.path().join("project1");
    let proj2 = tmp.path().join("project2");
    std::fs::create_dir_all(&proj1).unwrap();
    std::fs::create_dir_all(&proj2).unwrap();

    let result_p1 = link_packages_v2(
        &proj1,
        vec![
            target("c", "1.0.0", &c_sri, true),
            target("react", "18.0.0", &r_sri, false),
        ],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();
    let result_p2 = link_packages_v2(
        &proj2,
        vec![
            target("c", "1.0.0", &c_sri, true),
            target("react", "18.0.0", &r_sri, false),
        ],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    let c_dest_p1 = result_p1
        .materialized
        .iter()
        .find(|m| m.name == "c")
        .map(|m| m.destination.clone())
        .unwrap();
    let c_dest_p2 = result_p2
        .materialized
        .iter()
        .find(|m| m.name == "c")
        .map(|m| m.destination.clone())
        .unwrap();
    assert_eq!(
        c_dest_p1, c_dest_p2,
        "same edge graph + same peer pinning across two projects must share the link entry"
    );
}

#[test]
fn link_packages_v2_hoisted_mode_accepts_targets_with_peer_context() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let consumer_sri = synthetic_sri(b"hoisted_peers/consumer");
    write_object(
        &store,
        &consumer_sri,
        &[(
            "package.json",
            b"{\"name\":\"consumer\",\"version\":\"1.0.0\",\"peerDependencies\":{\"react\":\"*\"}}",
        )],
    );

    let react_sri = synthetic_sri(b"hoisted_peers/react");
    write_object(
        &store,
        &react_sri,
        &[(
            "package.json",
            b"{\"name\":\"react\",\"version\":\"18.3.1\"}",
        )],
    );

    let mut consumer = target("consumer", "1.0.0", &consumer_sri, true);
    consumer.target.peers = vec![("react".into(), "18.3.1".into())];
    let react = target("react", "18.3.1", &react_sri, false);

    let result = link_packages_v2(
        &project,
        vec![consumer, react],
        &store,
        LinkerMode::Hoisted,
        None,
    )
    .unwrap();

    assert_eq!(result.linked, 2);
    assert_eq!(result.symlinked, 1);
    assert!(project.join("node_modules").join("consumer").exists());
}

#[test]
fn link_packages_v2_hoisted_mode_splits_peer_divergent_projects() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));

    let consumer_sri = synthetic_sri(b"hoisted_peer_divergent/consumer");
    write_object(
        &store,
        &consumer_sri,
        &[(
            "package.json",
            b"{\"name\":\"consumer\",\"version\":\"1.0.0\"}",
        )],
    );

    let react_18_sri = synthetic_sri(b"hoisted_peer_divergent/react@18");
    write_object(
        &store,
        &react_18_sri,
        &[(
            "package.json",
            b"{\"name\":\"react\",\"version\":\"18.3.1\"}",
        )],
    );
    let react_19_sri = synthetic_sri(b"hoisted_peer_divergent/react@19");
    write_object(
        &store,
        &react_19_sri,
        &[(
            "package.json",
            b"{\"name\":\"react\",\"version\":\"19.0.0\"}",
        )],
    );

    let project_18 = tmp.path().join("project-18");
    std::fs::create_dir_all(&project_18).unwrap();
    let mut consumer_18 = target("consumer", "1.0.0", &consumer_sri, true);
    consumer_18.target.peers = vec![("react".into(), "18.3.1".into())];
    let result_18 = link_packages_v2(
        &project_18,
        vec![consumer_18, target("react", "18.3.1", &react_18_sri, false)],
        &store,
        LinkerMode::Hoisted,
        None,
    )
    .unwrap();

    let project_19 = tmp.path().join("project-19");
    std::fs::create_dir_all(&project_19).unwrap();
    let mut consumer_19 = target("consumer", "1.0.0", &consumer_sri, true);
    consumer_19.target.peers = vec![("react".into(), "19.0.0".into())];
    let result_19 = link_packages_v2(
        &project_19,
        vec![consumer_19, target("react", "19.0.0", &react_19_sri, false)],
        &store,
        LinkerMode::Hoisted,
        None,
    )
    .unwrap();

    let consumer_dest_18 = result_18
        .materialized
        .iter()
        .find(|m| m.name == "consumer")
        .map(|m| m.destination.clone())
        .expect("consumer materialized with react 18");
    let consumer_dest_19 = result_19
        .materialized
        .iter()
        .find(|m| m.name == "consumer")
        .map(|m| m.destination.clone())
        .expect("consumer materialized with react 19");
    assert_ne!(
        consumer_dest_18, consumer_dest_19,
        "hoisted v2 link entries must include peer pinning when peer siblings are materialized"
    );
}

#[test]
fn link_packages_v2_resolves_multi_source_same_coords_with_source_edges() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let registry_sri = synthetic_sri(b"multi_source/registry");
    let source_sri = synthetic_sri(b"multi_source/source");
    let consumer_sri = synthetic_sri(b"multi_source/consumer");
    write_object(
        &store,
        &registry_sri,
        &[
            ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 'registry';\n"),
        ],
    );
    write_object(
        &store,
        &source_sri,
        &[
            ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 'source';\n"),
        ],
    );
    write_object(
        &store,
        &consumer_sri,
        &[(
            "package.json",
            b"{\"name\":\"consumer\",\"version\":\"1.0.0\",\"dependencies\":{\"x\":\"1.0.0\"}}",
        )],
    );

    let registry_x = target("x", "1.0.0", &registry_sri, true);
    let mut source_x = target("x", "1.0.0", &source_sri, false);
    source_x.target.wrapper_id = Some("t-bbbbbbbbbbbbbbbb".into());
    let mut consumer = target("consumer", "1.0.0", &consumer_sri, true);
    consumer.target.dependencies = vec![LinkDependency::new(
        "x",
        "x",
        "1.0.0",
        Some("t-bbbbbbbbbbbbbbbb".into()),
    )];

    let result = link_packages_v2(
        &project,
        vec![registry_x, source_x, consumer],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(result.linked, 3);
    assert!(
        project
            .join("node_modules")
            .join("x")
            .join("index.js")
            .is_file()
    );

    let consumer_link_pkg = result
        .materialized
        .iter()
        .find(|m| m.name == "consumer")
        .map(|m| m.destination.clone())
        .unwrap();
    let consumer_link_dir = consumer_link_pkg.parent().unwrap().parent().unwrap();
    let source_sibling = consumer_link_dir.join("node_modules").join("x");
    assert_eq!(
        std::fs::read_to_string(source_sibling.join("index.js")).unwrap(),
        "module.exports = 'source';\n",
    );
}

// ── F1 — patch_fingerprint cross-project isolation ──────────────────
//
// **Load-bearing for the patch-engine contract under v2.** Patches
// are documented as repo-local (`crates/lpm-cli/src/commands/patch.rs:18`):
// "Patches travel with the repo. The next `lpm install` automatically
// re-applies them after linking." Under v2's cross-project link
// sharing, two projects with identical dep graphs
// resolve to the same `<store>/v2/links/<key>/...` directory by
// design. Without F1's `patch_fingerprint` dimension, project A's
// `apply_patch` mutation lands in the shared dir and project B's
// symlinks resolve through it — silently leaking patched bytes
// across project boundaries.
//
// The fix folds patch identity into the GraphKey so:
// 1. A patched install lands in its own `links/<key>+<patch-hash>/`
//    directory, distinct from any unpatched install of the same
//    coords.
// 2. Two projects applying byte-identical patches with the same
//    pinned baseline still share (correct — equivalent
//    materializations are interchangeable).
// 3. Edits to the patch text or `originalIntegrity` rotation split
//    into a fresh entry (old patched bytes can never leak forward).

#[test]
fn link_packages_v2_isolates_patched_install_from_unpatched() {
    // Two projects pin lodash@1.0.0 with identical dep graphs.
    // Project A declares a patch (carries `patch_fingerprint`);
    // project B is unpatched. The two installs MUST land at
    // different link-entry directories.
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));

    let sri = synthetic_sri(b"f1_isolation/lodash");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                b"{\"name\":\"lodash\",\"version\":\"1.0.0\"}",
            ),
            ("index.js", b"module.exports = 'orig';\n"),
        ],
    );

    let proj_a = tmp.path().join("project-a-patched");
    let proj_b = tmp.path().join("project-b-unpatched");
    std::fs::create_dir_all(&proj_a).unwrap();
    std::fs::create_dir_all(&proj_b).unwrap();

    let mut t_a = target("lodash", "1.0.0", &sri, true);
    t_a.target.patch_fingerprint = Some("p-aaaaaaaaaaaaaaaa".into());
    let t_b = target("lodash", "1.0.0", &sri, true); // unpatched

    let r_a = link_packages_v2(&proj_a, vec![t_a], &store, LinkerMode::Isolated, None).unwrap();
    let r_b = link_packages_v2(&proj_b, vec![t_b], &store, LinkerMode::Isolated, None).unwrap();

    let dest_a = r_a
        .materialized
        .iter()
        .find(|m| m.name == "lodash")
        .map(|m| m.destination.clone())
        .unwrap();
    let dest_b = r_b
        .materialized
        .iter()
        .find(|m| m.name == "lodash")
        .map(|m| m.destination.clone())
        .unwrap();
    assert_ne!(
        dest_a, dest_b,
        "patched install MUST land in a different link entry than \
             an unpatched install of the same coords — without this, \
             `apply_patch` mutates the dir project B's symlinks resolve \
             through, silently exporting the patch across projects"
    );

    // Byte-isolation cross-check: simulate what `apply_patch` does
    // (`remove_file` + `write` to break inode-share) on project A's
    // destination, then assert project B's bytes are pristine.
    // Combined with the assert_ne above this is the full F1
    // contract: distinct paths + distinct bytes after mutation.
    let a_file = dest_a.join("index.js");
    let b_file = dest_b.join("index.js");
    std::fs::remove_file(&a_file).unwrap();
    std::fs::write(&a_file, b"module.exports = 'PATCHED';\n").unwrap();

    let b_bytes = std::fs::read(&b_file).unwrap();
    assert_eq!(
        b_bytes, b"module.exports = 'orig';\n",
        "project B's bytes MUST remain pristine after project A patches its own link entry"
    );
}

#[test]
fn link_packages_v2_shares_link_entry_for_byte_identical_patches() {
    // Two projects applying byte-identical patches against the
    // same baseline SHOULD share a single link entry — that's the
    // whole point of content-derived patch fingerprinting (the
    // cheap, correct case the F1 design unlocks). Without this,
    // every project would pay a fresh materialization tax even
    // when the patched output is byte-equivalent.
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));

    let sri = synthetic_sri(b"f1_shared_patch/lodash");
    write_object(
        &store,
        &sri,
        &[(
            "package.json",
            b"{\"name\":\"lodash\",\"version\":\"1.0.0\"}",
        )],
    );

    let proj_a = tmp.path().join("project-a");
    let proj_b = tmp.path().join("project-b");
    std::fs::create_dir_all(&proj_a).unwrap();
    std::fs::create_dir_all(&proj_b).unwrap();

    let mut t_a = target("lodash", "1.0.0", &sri, true);
    t_a.target.patch_fingerprint = Some("p-1234567890abcdef".into());
    let mut t_b = target("lodash", "1.0.0", &sri, true);
    t_b.target.patch_fingerprint = Some("p-1234567890abcdef".into());

    let r_a = link_packages_v2(&proj_a, vec![t_a], &store, LinkerMode::Isolated, None).unwrap();
    let r_b = link_packages_v2(&proj_b, vec![t_b], &store, LinkerMode::Isolated, None).unwrap();

    let dest_a = r_a
        .materialized
        .iter()
        .find(|m| m.name == "lodash")
        .map(|m| m.destination.clone())
        .unwrap();
    let dest_b = r_b
        .materialized
        .iter()
        .find(|m| m.name == "lodash")
        .map(|m| m.destination.clone())
        .unwrap();
    assert_eq!(
        dest_a, dest_b,
        "byte-identical patch + identical baseline across two \
             projects MUST share the link entry"
    );
}

/// Parallel materialization above `PARALLEL_THRESHOLD = 32` must
/// produce the same `LinkResult` shape as the sequential path:
/// every input target gets a populated link entry, materialized
/// count matches the input length, and `linked` (count of
/// freshly-populated entries) sums correctly across rayon worker
/// threads via the atomic counter.
#[test]
fn link_packages_v2_parallel_materialization_above_threshold() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    // 50 distinct packages — comfortably above the 32-package
    // threshold so the parallel branch fires.
    const N: usize = 50;
    let mut targets = Vec::with_capacity(N);
    for i in 0..N {
        let name = format!("pkg-{i}");
        let sri = synthetic_sri(format!("parallel/{name}").as_bytes());
        let pkg_json = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
        write_object(&store, &sri, &[("package.json", pkg_json.as_bytes())]);
        targets.push(target(&name, "1.0.0", &sri, true));
    }

    let result = link_packages_v2(&project, targets, &store, LinkerMode::Isolated, None).unwrap();

    // Every package freshly populated: linked counter must match N.
    assert_eq!(
        result.linked, N,
        "atomic counter must sum correctly across rayon workers"
    );
    // Each direct dep gets one root symlink: symlinked must match N.
    assert_eq!(result.symlinked, N);
    // Materialized list preserves one entry per input.
    assert_eq!(result.materialized.len(), N);
    // Every materialized destination resolves to a real package
    // dir — proves the link entry was actually populated, not just
    // counted.
    for m in &result.materialized {
        assert!(
            m.destination.join("package.json").is_file(),
            "package dir {} must contain package.json post-materialization",
            m.destination.display()
        );
    }
    // Every project-side root symlink resolves through to the link
    // entry — confirms the post-parallel `create_root_symlinks`
    // pass saw all `N` graph keys via the key_map.
    for i in 0..N {
        let name = format!("pkg-{i}");
        let link = project.join("node_modules").join(&name);
        assert!(
            link.symlink_metadata().unwrap().file_type().is_symlink(),
            "project-side root symlink for {name} must exist after parallel materialization"
        );
        assert!(link.join("package.json").is_file());
    }
}

#[cfg(unix)]
const LOW_NOFILE_CHILD_ENV: &str = "LPM_LINKER_LOW_NOFILE_RELINK_CHILD";

#[cfg(unix)]
#[test]
fn warm_v2_relink_does_not_exhaust_file_descriptors_under_low_limit() {
    if std::env::var_os(LOW_NOFILE_CHILD_ENV).is_some() {
        run_warm_v2_relink_under_low_nofile();
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("warm_v2_relink_does_not_exhaust_file_descriptors_under_low_limit")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(LOW_NOFILE_CHILD_ENV, "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "low-RLIMIT_NOFILE child failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn run_warm_v2_relink_under_low_nofile() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    const PACKAGE_COUNT: usize = 33;
    const TREE_DEPTH: usize = 96;
    let mut targets = Vec::with_capacity(PACKAGE_COUNT);
    for i in 0..PACKAGE_COUNT {
        let name = format!("deep-pkg-{i}");
        let sri = synthetic_sri(format!("warm-low-nofile/{name}").as_bytes());
        write_deep_object(&store, &sri, &name, TREE_DEPTH);
        let verified = store
            .reusable_object(&sri)
            .unwrap()
            .unwrap()
            .object_integrity;
        let mut v2t = target(&name, "1.0.0", &sri, true);
        v2t.verified_object_integrity = Some(verified);
        targets.push(v2t);
    }

    let first = link_packages_v2(
        &project,
        targets.clone(),
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();
    assert_eq!(first.linked, PACKAGE_COUNT);
    std::fs::remove_dir_all(project.join("node_modules")).unwrap();

    let _limit = NofileLimitGuard::lower_to(64);
    let second = link_packages_v2(&project, targets, &store, LinkerMode::Isolated, None).unwrap();

    assert_eq!(second.linked, 0);
    assert_eq!(second.skipped, PACKAGE_COUNT);
    assert_eq!(second.symlinked, PACKAGE_COUNT);
}

#[cfg(unix)]
fn write_deep_object(store: &V2Store, sri: &str, name: &str, depth: usize) {
    let package_json = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
    let mut deep_path = String::new();
    for i in 0..depth {
        if !deep_path.is_empty() {
            deep_path.push('/');
        }
        deep_path.push_str(&format!("d{i:02}"));
    }
    deep_path.push_str("/index.js");

    let files = [
        ("package.json", package_json.as_bytes()),
        (deep_path.as_str(), b"module.exports = {};\n".as_slice()),
    ];
    write_object(store, sri, &files);
}

#[cfg(unix)]
struct NofileLimitGuard {
    previous: libc::rlimit,
}

#[cfg(unix)]
impl NofileLimitGuard {
    fn lower_to(soft: libc::rlim_t) -> Self {
        let mut previous = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `previous` points to valid writable storage for the kernel result.
        let get_rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut previous) };
        assert_eq!(get_rc, 0, "getrlimit(RLIMIT_NOFILE) failed");
        assert!(
            previous.rlim_cur > soft,
            "test requires an initial RLIMIT_NOFILE above {soft}, got {}",
            previous.rlim_cur
        );

        let mut lowered = previous;
        lowered.rlim_cur = soft.min(previous.rlim_max);
        // SAFETY: `lowered` is a valid rlimit for RLIMIT_NOFILE and only lowers the soft cap.
        let set_rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) };
        assert_eq!(set_rc, 0, "setrlimit(RLIMIT_NOFILE) failed");
        Self { previous }
    }
}

#[cfg(unix)]
impl Drop for NofileLimitGuard {
    fn drop(&mut self) {
        // SAFETY: restores the rlimit value captured from a successful getrlimit call.
        let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.previous) };
    }
}

/// A package whose `bin` map keys a shim with a path-traversal
/// name must be skipped. v1's hoisted emitter has enforced this
/// since the validators were introduced; v2 (the default store
/// version) was the gap a malicious package could exploit to
/// shadow `/usr/bin` entries via `node_modules/.bin/`.
#[test]
fn v2_skips_bin_shim_when_bin_name_contains_path_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/bin_name_traversal");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                br#"{"name":"a","version":"1.0.0","bin":{"../escape":"index.js"}}"#,
            ),
            ("index.js", b"console.log('a');"),
        ],
    );

    let result = link_packages_v2(
        &project,
        vec![target("a", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(
        result.bin_linked, 0,
        "bin name with `..` must be rejected by validate_bin_name",
    );
    let bin_dir = project.join("node_modules").join(".bin");
    if bin_dir.exists() {
        assert!(
            std::fs::read_dir(&bin_dir).unwrap().next().is_none(),
            ".bin/ must stay empty when the only entry was rejected",
        );
    }
}

/// A package whose `bin` value points outside its own dir (the
/// classic `"bin": {"x": "../../bin/sh"}` shape) must be skipped.
/// `validate_bin_target` catches the `..` component in the joined
/// path before any symlink is created.
#[test]
fn v2_skips_bin_shim_when_bin_target_escapes_package_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/bin_target_traversal");
    write_object(
        &store,
        &sri,
        &[(
            "package.json",
            br#"{"name":"a","version":"1.0.0","bin":{"x":"../../../bin/sh"}}"#,
        )],
    );

    let result = link_packages_v2(
        &project,
        vec![target("a", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(
        result.bin_linked, 0,
        "bin target with `..` components must be rejected by validate_bin_target",
    );
    let shim = project.join("node_modules").join(".bin").join("x");
    assert!(
        shim.symlink_metadata().is_err(),
        "no shim should be created for an escaping bin target",
    );
}

/// Benign shape still works — proves the new validators don't
/// over-reject. A well-formed bin entry pointing at an in-package
/// file produces an executable `.bin/` shim.
#[test]
fn v2_creates_bin_shim_for_well_formed_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/bin_ok");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                br#"{"name":"a","version":"1.0.0","bin":{"a":"cli.js"}}"#,
            ),
            ("cli.js", b"#!/usr/bin/env node\nconsole.log('hi');\n"),
        ],
    );

    let result = link_packages_v2(
        &project,
        vec![target("a", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert_eq!(result.bin_linked, 1, "well-formed bin entry must be linked");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let shim = project.join("node_modules").join(".bin").join("a");
        assert!(
            shim.symlink_metadata().unwrap().file_type().is_file(),
            "non-executable bin target should produce a wrapper file",
        );
        assert_eq!(
            shim.metadata().unwrap().permissions().mode() & 0o111,
            0o111,
            "wrapper shim must be executable",
        );
    }
}

#[cfg(unix)]
#[test]
fn link_packages_v2_reuses_up_to_date_bin_shim_on_warm_rerun() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/bin_warm_reuse");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                br#"{"name":"a","version":"1.0.0","bin":{"a":"cli.js"}}"#,
            ),
            ("cli.js", b"#!/usr/bin/env node\nconsole.log('hi');\n"),
        ],
    );
    let package = target("a", "1.0.0", &sri, true);

    let first = link_packages_v2(
        &project,
        vec![package.clone()],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();
    assert_eq!(first.bin_linked, 1, "first run must create the shim");

    let shim = project.join("node_modules").join(".bin").join("a");
    let package_bin = first.materialized[0].destination.join("cli.js");
    assert_eq!(
        std::fs::metadata(&package_bin)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "v2 bin shim creation must not chmod the shared link entry target"
    );
    let first_content = std::fs::read_to_string(&shim).expect("shim should be a wrapper file");
    let first_inode = shim.symlink_metadata().expect("shim metadata").ino();

    let second =
        link_packages_v2(&project, vec![package], &store, LinkerMode::Isolated, None).unwrap();
    assert_eq!(
        second.linked, 0,
        "warm rerun must reuse the existing link entry for direct-bin packages"
    );
    assert_eq!(
        second.bin_linked, 1,
        "warm rerun should still report the usable shim"
    );
    assert_eq!(
        std::fs::read_to_string(&shim).expect("shim should remain a wrapper file"),
        first_content,
        "warm rerun must keep the same wrapper content"
    );
    assert_eq!(
        shim.symlink_metadata().expect("shim metadata").ino(),
        first_inode,
        "warm rerun must not unlink and recreate an already-correct shim"
    );
    assert_eq!(
        std::fs::metadata(&package_bin)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "warm rerun must leave the link entry target unmodified"
    );
}

#[cfg(unix)]
#[test]
fn link_packages_v2_repairs_stale_bin_shim_target() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/bin_stale_target");
    write_object(
        &store,
        &sri,
        &[
            (
                "package.json",
                br#"{"name":"a","version":"1.0.0","bin":{"a":"cli.js"}}"#,
            ),
            ("cli.js", b"#!/usr/bin/env node\nconsole.log('hi');\n"),
        ],
    );
    let package = target("a", "1.0.0", &sri, true);
    link_packages_v2(
        &project,
        vec![package.clone()],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    let shim = project.join("node_modules").join(".bin").join("a");
    std::fs::remove_file(&shim).unwrap();
    std::os::unix::fs::symlink("../wrong-target.js", &shim).unwrap();

    let second =
        link_packages_v2(&project, vec![package], &store, LinkerMode::Isolated, None).unwrap();
    assert_eq!(second.bin_linked, 1, "repaired shim should be counted");

    assert!(
        shim.symlink_metadata().unwrap().file_type().is_file(),
        "stale symlink should be replaced by the wrapper shim"
    );
    assert!(
        std::fs::read_to_string(&shim).unwrap().contains("cli.js"),
        "repaired wrapper must execute the declared bin target",
    );
}

#[test]
fn link_packages_v2_removes_stale_bin_shims_when_bins_disappear() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let with_bin_sri = synthetic_sri(b"v2/stale-bin/with");
    write_object(
        &store,
        &with_bin_sri,
        &[
            (
                "package.json",
                br#"{"name":"a","version":"1.0.0","bin":{"a":"cli.js"}}"#,
            ),
            ("cli.js", b"#!/usr/bin/env node\nconsole.log('hi');\n"),
        ],
    );
    link_packages_v2(
        &project,
        vec![target("a", "1.0.0", &with_bin_sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();
    assert!(project.join("node_modules").join(".bin").join("a").exists());

    let without_bin_sri = synthetic_sri(b"v2/stale-bin/without");
    write_object(
        &store,
        &without_bin_sri,
        &[("package.json", b"{\"name\":\"a\",\"version\":\"2.0.0\"}")],
    );
    link_packages_v2(
        &project,
        vec![target("a", "2.0.0", &without_bin_sri, true)],
        &store,
        LinkerMode::Isolated,
        None,
    )
    .unwrap();

    assert!(!project.join("node_modules").join(".bin").join("a").exists());
}

/// A root link name with `..` would escape `node_modules/` and could
/// delete arbitrary content during stale-slot cleanup. `root_link_names`
/// filters such names with a warn-and-continue posture.
#[test]
fn root_link_names_rejects_path_traversal_components() {
    let bad = [
        "..",
        "../escape",
        "scope/../escape",
        "deep/../../escape",
        "with\\backslash",
        "with\0null",
        "",
    ];
    for name in bad {
        assert!(
            !is_safe_root_link_name(name),
            "name {name:?} must be rejected as unsafe",
        );
    }
}

/// Positive baseline: legitimate names (plain + scoped) are
/// accepted so the filter doesn't over-reject.
#[test]
fn root_link_names_accepts_plain_and_scoped_names() {
    for name in ["react", "lodash", "@scope/foo", "@a/b", "a-package_name"] {
        assert!(
            is_safe_root_link_name(name),
            "name {name:?} must be accepted",
        );
    }
}

/// End-to-end through link_packages_v2: a target whose
/// `root_link_names` contains `..` MUST NOT create a symlink
/// outside `<project>/node_modules/`. Pre-fix this would have
/// landed a `remove_dir_all` against the escaped path.
#[test]
fn link_packages_v2_skips_root_symlink_when_name_contains_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let sri = synthetic_sri(b"v2/root_link_traversal");
    write_object(
        &store,
        &sri,
        &[("package.json", b"{\"name\":\"safe\",\"version\":\"1.0.0\"}")],
    );

    let mut t = target("safe", "1.0.0", &sri, true);
    t.target.root_link_names = Some(vec!["../escape".into(), "safe".into()]);

    let result = link_packages_v2(&project, vec![t], &store, LinkerMode::Isolated, None).unwrap();

    // Only the safe `safe` symlink should land — the `../escape`
    // entry filtered out by root_link_names.
    assert_eq!(
        result.symlinked, 1,
        "exactly one (safe) root symlink should land",
    );
    assert!(
        project
            .join("node_modules")
            .join("safe")
            .symlink_metadata()
            .is_ok(),
        "safe root symlink must exist",
    );
    // The escape path must not have been touched.
    assert!(
        !project.join("escape").exists(),
        "no `escape` entry should be created outside node_modules",
    );
}

#[cfg(unix)]
#[test]
fn link_v2_finalize_replaces_symlinked_scope_parent_before_root_symlink_write() {
    let tmp = tempfile::tempdir().unwrap();
    let store = V2Store::at(tmp.path().join("store"));
    let project = tmp.path().join("project");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let sri = synthetic_sri(b"v2/scope_parent_symlink");
    write_object(
        &store,
        &sri,
        &[(
            "package.json",
            b"{\"name\":\"@scope/pkg\",\"version\":\"1.0.0\"}",
        )],
    );

    let plan = link_v2_prepare(
        &project,
        vec![target("@scope/pkg", "1.0.0", &sri, true)],
        &store,
        LinkerMode::Isolated,
    )
    .unwrap();
    link_v2_one(&plan, &plan.augmented_targets[0], &store).unwrap();

    std::fs::create_dir_all(project.join("node_modules")).unwrap();
    let scope_dir = project.join("node_modules").join("@scope");
    std::os::unix::fs::symlink(&outside, &scope_dir).unwrap();

    let result = link_v2_finalize(&project, &plan, &store, None).unwrap();

    assert_eq!(result.symlinked, 1);
    assert!(
        scope_dir.symlink_metadata().unwrap().file_type().is_dir(),
        "finalize must replace a symlinked scope parent with a real directory",
    );
    assert!(
        !scope_dir
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "scope parent must not remain a symlink",
    );
    assert!(
        !outside.join("pkg").exists(),
        "root symlink must not be created through a symlinked scope parent",
    );
    let root_link = scope_dir.join("pkg");
    assert!(
        root_link
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "scoped root link must be recreated under the real scope directory",
    );
    let key = plan
        .key_map
        .get_for(&plan.augmented_targets[0].target)
        .unwrap();
    assert!(
        symlink_points_to(&root_link, &store.paths().link_package_dir(key)),
        "scoped root link should point at the v2 link package dir",
    );
}
