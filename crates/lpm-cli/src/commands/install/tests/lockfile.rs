use super::*;

use lpm_resolver::NpmVersion;
use lpm_resolver::ResolverPackage;
use std::io::{self, Write};
use std::sync::Mutex;
use tracing_subscriber::fmt::MakeWriter;

const VALID_SHA512_SRI: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const TEST_REGISTRY_SOURCE: &str = "registry+https://registry.npmjs.org";

#[derive(Clone, Default)]
struct ReplayWarningBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for ReplayWarningBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("trace buffer poisoned").extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for ReplayWarningBuffer {
    type Writer = ReplayWarningBuffer;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn current_leaf_lockfile(name: &str, version: &str, source: &str) -> lpm_lockfile::Lockfile {
    let instance_id =
        lpm_common::PackageInstanceId::derive(name, version, source, &format!("root/{name}"));
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: name.to_string(),
        version: version.to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        name.to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: name.to_string(),
            version: version.to_string(),
            source: Some(source.to_string()),
        },
    );
    lockfile
}

fn binary_representable_leaf_lockfile(name: &str, version: &str) -> lpm_lockfile::Lockfile {
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: name.to_string(),
        version: version.to_string(),
        source: Some(TEST_REGISTRY_SOURCE.to_string()),
        ..Default::default()
    });
    lockfile
}

#[test]
fn lockfile_replay_warning_redacts_source_credentials_and_url_components() {
    let source = "registry+https://source-user:source-password@example.invalid/private-path?token=query-secret#fragment-secret";
    let lockfile = current_leaf_lockfile("unsafe-source", "1.0.0", source);
    let package_rows = lockfile.packages.iter().collect::<Vec<_>>();
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = RegistryClient::new();
    let output = ReplayWarningBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_level(false)
        .with_ansi(false)
        .with_writer(output.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        assert!(!lockfile_satisfies_fast_path_with_packages(
            &lockfile,
            &package_rows,
            LockfileReplayInput {
                lockfile_dir: Path::new("."),
                deps: &HashMap::new(),
                catalog_resolutions: &[],
                workspace: None,
                registry_source: RegistrySourceContext::new(&route_table, &client),
                policy: LockfileReplayPolicy {
                    accept_unsafe_sources: false,
                    emit_warnings: true,
                },
            },
        ));
    });

    let rendered = String::from_utf8(output.0.lock().expect("trace buffer poisoned").clone())
        .expect("trace output must be UTF-8");
    assert!(rendered.contains("registry+https://example.invalid"));
    for secret in [
        "source-user",
        "source-password",
        "private-path",
        "query-secret",
        "fragment-secret",
    ] {
        assert!(
            !rendered.contains(secret),
            "replay warning exposed {secret:?}: {rendered}"
        );
    }
}

#[test]
fn importer_snapshot_with_peer_install_state_is_authoritative() {
    let snapshot = lpm_lockfile::ImporterSnapshot {
        auto_install_peers: Some(false),
        ..Default::default()
    };

    assert!(importer_snapshot_is_authoritative(&snapshot));
}

#[test]
fn importer_snapshot_without_peer_install_state_is_legacy() {
    assert!(!importer_snapshot_is_authoritative(
        &lpm_lockfile::ImporterSnapshot::default()
    ));
}

fn fake_resolved(name: &str, version: &str, context: Option<&str>) -> ResolvedPackage {
    let mut hash = 2_166_136_261_u32;
    for byte in name
        .bytes()
        .chain(version.bytes())
        .chain(context.into_iter().flat_map(str::bytes))
    {
        hash = hash.wrapping_mul(16_777_619) ^ u32::from(byte);
    }
    fake_resolved_at(hash, name, version, context)
}

fn fake_resolved_at(
    resolution_id: u32,
    name: &str,
    version: &str,
    context: Option<&str>,
) -> ResolvedPackage {
    let pkg = match context {
        Some(ctx) => ResolverPackage::npm(name).with_context(ctx),
        None => ResolverPackage::npm(name),
    };
    ResolvedPackage {
        resolution_id: lpm_common::ResolutionNodeId::new(resolution_id),
        dependency_targets: HashMap::new(),
        optional_dependencies: HashSet::new(),
        peer_targets: HashMap::new(),
        package: pkg,
        version: NpmVersion::parse(version).expect("valid version"),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        node_engine: None,
        optional: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolved_to_install_packages(
    resolved: &[ResolvedPackage],
    deps: &HashMap<String, String>,
    root_aliases: &HashMap<String, String>,
    _root_resolutions: &HashMap<String, lpm_resolver::RootResolution>,
    ambient_peer_installs: &[String],
    resolver_cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    registry_source: RegistrySourceContext<'_>,
) -> Vec<InstallPackage> {
    let roots = resolved
        .iter()
        .enumerate()
        .map(|(index, package)| {
            (
                format!("test-root-{index}"),
                lpm_resolver::RootResolution {
                    target: package.resolution_id,
                    package: package.package.canonical_name(),
                    version: package.version.to_string(),
                },
            )
        })
        .collect();
    super::resolved_to_install_packages(
        resolved,
        deps,
        root_aliases,
        &roots,
        ambient_peer_installs,
        resolver_cache,
        registry_source,
    )
    .expect("fixture graph must have complete exact roots")
}

fn filter_fixture_package(
    name: &str,
    source: &str,
    root_link_name: Option<&str>,
    optional: bool,
) -> InstallPackage {
    InstallPackage {
        instance_id: None,
        dependency_targets: HashMap::new(),
        peer_targets: HashMap::new(),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: source.to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: root_link_name.map(|name| vec![name.to_string()]),
        is_direct: root_link_name.is_some(),
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        unpacked_size: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional,
        tarball_url: None,
        metadata_checked_for_tarball: false,
        manifest_fingerprint: None,
    }
}

#[test]
fn platform_skip_preserves_required_registry_edge_with_same_name_and_version() {
    let registry_source = "registry+https://registry.npmjs.org";
    let mut host = filter_fixture_package(
        "registry-host",
        registry_source,
        Some("registry-host"),
        false,
    );
    host.dependencies
        .push(("foo".to_string(), "1.0.0".to_string()));
    let registry_foo = filter_fixture_package("foo", registry_source, None, false);
    let mut local_foo =
        filter_fixture_package("foo", "directory+./local-foo", Some("local-foo"), true);
    local_foo.platform = Some(lpm_resolver::PlatformMeta {
        os: vec!["__lpm_no_such_os__".to_string()],
        cpu: Vec::new(),
        libc: Vec::new(),
    });
    let mut packages = vec![host, registry_foo, local_foo];

    assert_eq!(filter_platform_packages(&mut packages).unwrap(), 1);

    let host = packages
        .iter()
        .find(|package| package.name == "registry-host")
        .expect("registry host must remain");
    assert_eq!(
        host.dependencies,
        vec![("foo".to_string(), "1.0.0".to_string())]
    );
    assert!(packages.iter().any(|package| {
        package.name == "foo" && package.source == registry_source && package.version == "1.0.0"
    }));
}

#[test]
fn optional_filter_removes_optional_only_roots_and_descendants() {
    let registry_source = "registry+https://registry.npmjs.org";
    let mut required = filter_fixture_package("required", registry_source, Some("required"), false);
    required
        .dependencies
        .push(("shared".to_string(), "1.0.0".to_string()));
    let mut optional = filter_fixture_package("optional", registry_source, Some("optional"), true);
    optional
        .dependencies
        .push(("optional-leaf".to_string(), "1.0.0".to_string()));
    let shared = filter_fixture_package("shared", registry_source, None, false);
    let optional_leaf = filter_fixture_package("optional-leaf", registry_source, None, true);
    let mut packages = vec![required, optional, shared, optional_leaf];

    assert_eq!(
        filter_optional_packages(&mut packages, &HashSet::from(["optional".to_string()])),
        2
    );
    assert_eq!(
        packages
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>(),
        vec!["required", "shared"]
    );
}

#[test]
fn optional_filter_removes_transitive_optional_package_without_optional_root() {
    let registry_source = "registry+https://registry.npmjs.org";
    let mut required = filter_fixture_package("required", registry_source, Some("required"), false);
    required
        .dependencies
        .push(("optional-child".to_string(), "1.0.0".to_string()));
    let optional_child = filter_fixture_package("optional-child", registry_source, None, true);
    let mut packages = vec![required, optional_child];

    assert_eq!(filter_optional_packages(&mut packages, &HashSet::new()), 1);
    assert_eq!(
        packages
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>(),
        vec!["required"]
    );
    assert!(packages[0].dependencies.is_empty());
}

#[test]
fn optional_filter_preserves_package_reached_by_required_alias() {
    let registry_source = "registry+https://registry.npmjs.org";
    let mut package = filter_fixture_package("shared", registry_source, None, false);
    package.root_link_names = Some(vec!["required-alias".into(), "optional-alias".into()]);
    package.is_direct = true;
    let mut packages = vec![package];

    assert_eq!(
        filter_optional_packages(
            &mut packages,
            &HashSet::from(["optional-alias".to_string()])
        ),
        0
    );
    assert_eq!(
        packages[0].root_link_names.as_deref(),
        Some(["required-alias".to_string()].as_slice())
    );
}

#[test]
fn prepare_override_resolution_state_resolves_catalog_backed_override_maps() {
    let mut package = lpm_workspace::PackageJson {
        catalogs: HashMap::from([
            (
                "default".to_string(),
                HashMap::from([("react".to_string(), "^19.0.0".to_string())]),
            ),
            (
                "testing".to_string(),
                HashMap::from([("left-pad".to_string(), "~1.3.0".to_string())]),
            ),
        ]),
        overrides: HashMap::from([("left-pad".to_string(), "catalog:testing".to_string())]),
        resolutions: HashMap::from([("chalk".to_string(), "^5.0.0".to_string())]),
        ..Default::default()
    };
    package.lpm = Some(lpm_workspace::LpmConfig {
        overrides: HashMap::from([("react".to_string(), "catalog:".to_string())]),
        ..Default::default()
    });
    let mut catalog_resolutions = vec![lpm_workspace::CatalogProtocolResolution {
        catalog_name: "default".to_string(),
        package_name: "existing".to_string(),
        reference: "catalog:".to_string(),
        specifier: "^1.0.0".to_string(),
    }];

    let state = prepare_override_resolution_state(OverrideResolutionInput {
        package: &package,
        workspace: None,
        catalog_resolutions: &mut catalog_resolutions,
    })
    .expect("catalog-backed overrides should resolve");

    assert_eq!(
        state.lpm_overrides.get("react").map(String::as_str),
        Some("^19.0.0")
    );
    assert_eq!(
        state.overrides.as_ref().get("left-pad").map(String::as_str),
        Some("~1.3.0")
    );
    assert_eq!(
        state.resolutions.as_ref().get("chalk").map(String::as_str),
        Some("^5.0.0")
    );
    assert_eq!(state.override_set.len(), 3);
    assert_eq!(state.dependency_catalog_resolution_count, 1);
    assert_eq!(state.override_catalog_resolutions.len(), 2);
    assert_eq!(catalog_resolutions.len(), 3);
}

#[test]
fn prepare_override_resolution_state_inherits_root_maps_with_member_precedence() {
    let mut root_package = lpm_workspace::PackageJson {
        overrides: HashMap::from([
            ("root-npm".to_string(), "1.0.0".to_string()),
            ("shared-npm".to_string(), "1.0.0".to_string()),
        ]),
        resolutions: HashMap::from([
            ("root-yarn".to_string(), "1.0.0".to_string()),
            ("shared-yarn".to_string(), "1.0.0".to_string()),
        ]),
        ..Default::default()
    };
    root_package.lpm = Some(lpm_workspace::LpmConfig {
        overrides: HashMap::from([
            ("root-lpm".to_string(), "1.0.0".to_string()),
            ("shared-lpm".to_string(), "1.0.0".to_string()),
        ]),
        ..Default::default()
    });
    let workspace = lpm_workspace::Workspace {
        root: std::path::PathBuf::from("/workspace"),
        root_package,
        members: Vec::new(),
    };
    let mut member_package = lpm_workspace::PackageJson {
        overrides: HashMap::from([("shared-npm".to_string(), "2.0.0".to_string())]),
        resolutions: HashMap::from([("shared-yarn".to_string(), "2.0.0".to_string())]),
        ..Default::default()
    };
    member_package.lpm = Some(lpm_workspace::LpmConfig {
        overrides: HashMap::from([("shared-lpm".to_string(), "2.0.0".to_string())]),
        ..Default::default()
    });
    let mut catalog_resolutions = Vec::new();

    let state = prepare_override_resolution_state(OverrideResolutionInput {
        package: &member_package,
        workspace: Some(&workspace),
        catalog_resolutions: &mut catalog_resolutions,
    })
    .expect("workspace override maps should merge");

    assert_eq!(
        state.lpm_overrides.get("root-lpm").map(String::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        state.lpm_overrides.get("shared-lpm").map(String::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        state.overrides.get("root-npm").map(String::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        state.overrides.get("shared-npm").map(String::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        state.resolutions.get("root-yarn").map(String::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        state.resolutions.get("shared-yarn").map(String::as_str),
        Some("2.0.0")
    );
}

fn catalog_resolution(
    package_name: &str,
    specifier: &str,
) -> lpm_workspace::CatalogProtocolResolution {
    lpm_workspace::CatalogProtocolResolution {
        catalog_name: "default".to_string(),
        package_name: package_name.to_string(),
        reference: "catalog:".to_string(),
        specifier: specifier.to_string(),
    }
}

fn add_catalog_snapshot(
    lockfile: &mut lpm_lockfile::Lockfile,
    resolution: &lpm_workspace::CatalogProtocolResolution,
    version: &str,
) {
    let source = TEST_REGISTRY_SOURCE;
    let instance_id = lpm_common::PackageInstanceId::derive(
        &resolution.package_name,
        version,
        source,
        &format!("root/{}", resolution.package_name),
    );
    lockfile
        .catalogs
        .entry(resolution.catalog_name.clone())
        .or_default()
        .insert(
            resolution.package_name.clone(),
            lpm_lockfile::CatalogSnapshotEntry {
                specifier: resolution.specifier.clone(),
                version: version.to_string(),
                reference: resolution.reference.clone(),
            },
        );
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: resolution.package_name.clone(),
        version: version.to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        resolution.package_name.clone(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: resolution.package_name.clone(),
            version: version.to_string(),
            source: Some(source.to_string()),
        },
    );
}

#[test]
fn lockfile_catalog_replay_allows_configured_override_that_was_not_applied() {
    let direct = catalog_resolution("direct-package", "^1.0.0");
    let applied_override = catalog_resolution("applied-override", "^2.0.0");
    let unused_override = catalog_resolution("unused-override", "^3.0.0");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    add_catalog_snapshot(&mut lockfile, &direct, "1.1.0");
    add_catalog_snapshot(&mut lockfile, &applied_override, "2.1.0");
    let deps = HashMap::from([(direct.package_name.clone(), direct.specifier.clone())]);

    assert!(lockfile_catalog_snapshots_match_current(
        &lockfile,
        &deps,
        &[direct, applied_override, unused_override],
    ));
}

#[test]
fn lockfile_catalog_replay_rejects_missing_direct_snapshot() {
    let direct = catalog_resolution("direct-package", "^1.0.0");
    let deps = HashMap::from([(direct.package_name.clone(), direct.specifier.clone())]);

    assert!(!lockfile_catalog_snapshots_match_current(
        &lpm_lockfile::Lockfile::new(),
        &deps,
        &[direct],
    ));
}

#[test]
fn lockfile_catalog_replay_rejects_snapshot_for_removed_override() {
    let direct = catalog_resolution("direct-package", "^1.0.0");
    let removed_override = catalog_resolution("removed-override", "^2.0.0");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    add_catalog_snapshot(&mut lockfile, &direct, "1.1.0");
    add_catalog_snapshot(&mut lockfile, &removed_override, "2.1.0");
    let deps = HashMap::from([(direct.package_name.clone(), direct.specifier.clone())]);

    assert!(!lockfile_catalog_snapshots_match_current(
        &lockfile,
        &deps,
        &[direct],
    ));
}

#[test]
fn lockfile_catalog_replay_rejects_changed_specifier_or_reference() {
    let locked_resolution = catalog_resolution("direct-package", "^1.0.0");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    add_catalog_snapshot(&mut lockfile, &locked_resolution, "1.1.0");
    let deps = HashMap::from([(
        locked_resolution.package_name.clone(),
        locked_resolution.specifier.clone(),
    )]);
    let mut changed_specifier = locked_resolution.clone();
    changed_specifier.specifier = "^1.1.0".to_string();
    let mut changed_reference = locked_resolution;
    changed_reference.reference = "catalog:testing".to_string();

    assert!(!lockfile_catalog_snapshots_match_current(
        &lockfile,
        &deps,
        &[changed_specifier],
    ));
    assert!(!lockfile_catalog_snapshots_match_current(
        &lockfile,
        &deps,
        &[changed_reference],
    ));
}

#[test]
fn lockfile_catalog_replay_rejects_snapshot_version_drift() {
    let direct = catalog_resolution("direct-package", "^1.0.0");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    add_catalog_snapshot(&mut lockfile, &direct, "1.1.0");
    lockfile
        .catalogs
        .get_mut("default")
        .and_then(|catalog| catalog.get_mut("direct-package"))
        .expect("catalog snapshot")
        .version = "1.2.0".to_string();
    let deps = HashMap::from([(direct.package_name.clone(), direct.specifier.clone())]);

    assert!(!lockfile_catalog_snapshots_match_current(
        &lockfile,
        &deps,
        &[direct],
    ));
}

#[test]
fn resolved_to_install_packages_preserves_same_artifact_siblings_with_exact_targets() {
    let mut left_parent = fake_resolved_at(1, "left-parent", "1.0.0", None);
    left_parent
        .dependencies
        .push(("plugin".to_string(), "1.0.0".to_string()));
    left_parent
        .dependency_targets
        .insert("plugin".to_string(), lpm_common::ResolutionNodeId::new(3));
    let mut right_parent = fake_resolved_at(2, "right-parent", "1.0.0", None);
    right_parent
        .dependencies
        .push(("plugin".to_string(), "1.0.0".to_string()));
    right_parent
        .dependency_targets
        .insert("plugin".to_string(), lpm_common::ResolutionNodeId::new(4));
    let resolved = vec![
        left_parent,
        right_parent,
        fake_resolved_at(3, "plugin", "1.0.0", Some("without-runtime")),
        fake_resolved_at(4, "plugin", "1.0.0", Some("with-runtime")),
    ];
    let deps = HashMap::from([
        ("left-parent".to_string(), "1.0.0".to_string()),
        ("right-parent".to_string(), "1.0.0".to_string()),
    ]);
    let roots = HashMap::from([
        (
            "left-parent".to_string(),
            lpm_resolver::RootResolution {
                target: lpm_common::ResolutionNodeId::new(1),
                package: "left-parent".to_string(),
                version: "1.0.0".to_string(),
            },
        ),
        (
            "right-parent".to_string(),
            lpm_resolver::RootResolution {
                target: lpm_common::ResolutionNodeId::new(2),
                package: "right-parent".to_string(),
                version: "1.0.0".to_string(),
            },
        ),
    ]);

    let installed = super::resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &roots,
        &[],
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    )
    .expect("exact graph must convert");

    let plugins = installed
        .iter()
        .filter(|package| package.name == "plugin")
        .collect::<Vec<_>>();
    assert_eq!(plugins.len(), 2);
    assert_ne!(plugins[0].instance_id, plugins[1].instance_id);
    assert_eq!(
        installed[0].dependency_targets["plugin"],
        plugins[0].instance_id.expect("plugin instance id")
    );
    assert_eq!(
        installed[1].dependency_targets["plugin"],
        plugins[1].instance_id.expect("plugin instance id")
    );
}

#[test]
fn written_lockfile_replay_preserves_contextual_instances_edges_and_roots() {
    let registry_source = "registry+https://registry.npmjs.org";
    let left_id = lpm_common::PackageInstanceId::derive(
        "left-parent",
        "1.0.0",
        registry_source,
        "root/left-parent",
    );
    let right_id = lpm_common::PackageInstanceId::derive(
        "right-parent",
        "1.0.0",
        registry_source,
        "root/right-parent",
    );
    let first_plugin_id = lpm_common::PackageInstanceId::derive(
        "plugin",
        "1.0.0",
        registry_source,
        "root/left-parent/plugin",
    );
    let second_plugin_id = lpm_common::PackageInstanceId::derive(
        "plugin",
        "1.0.0",
        registry_source,
        "root/right-parent/plugin",
    );
    let mut left = filter_fixture_package("left-parent", registry_source, Some("left"), false);
    left.instance_id = Some(left_id);
    left.dependencies
        .push(("plugin".to_string(), "1.0.0".to_string()));
    left.dependency_targets
        .insert("plugin".to_string(), first_plugin_id);
    let mut right = filter_fixture_package("right-parent", registry_source, Some("right"), false);
    right.instance_id = Some(right_id);
    right
        .dependencies
        .push(("plugin".to_string(), "1.0.0".to_string()));
    right
        .dependency_targets
        .insert("plugin".to_string(), second_plugin_id);
    let mut first_plugin = filter_fixture_package("plugin", registry_source, None, false);
    first_plugin.instance_id = Some(first_plugin_id);
    let mut second_plugin = first_plugin.clone();
    second_plugin.instance_id = Some(second_plugin_id);
    let packages = vec![left, right, first_plugin, second_plugin];

    let mut lockfile = lpm_lockfile::Lockfile::new();
    for package in &packages {
        lockfile.add_package(locked_package_from_install_package(package));
    }
    lockfile.root_aliases = root_aliases_for_lockfile(&packages, &HashMap::new());
    lockfile.root_resolutions = root_resolutions_for_lockfile(&packages);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(lpm_lockfile::LOCKFILE_NAME);
    lockfile.write_to_file(&path).expect("write exact graph");
    let deps = HashMap::from([
        ("left".to_string(), "1.0.0".to_string()),
        ("right".to_string(), "1.0.0".to_string()),
    ]);

    let replay = try_lockfile_fast_path(
        &path,
        &deps,
        &[],
        None,
        &RegistryClient::new(),
        &GateStats::default(),
        false,
    )
    .expect("current lockfile must replay");

    assert_eq!(replay.packages.len(), 4);
    let left = replay
        .packages
        .iter()
        .find(|package| package.instance_id == Some(left_id))
        .unwrap();
    let right = replay
        .packages
        .iter()
        .find(|package| package.instance_id == Some(right_id))
        .unwrap();
    assert_eq!(left.dependency_targets["plugin"], first_plugin_id);
    assert_eq!(right.dependency_targets["plugin"], second_plugin_id);
    assert_eq!(left.root_link_names.as_ref().unwrap(), &["left"]);
    assert_eq!(right.root_link_names.as_ref().unwrap(), &["right"]);
}

#[test]
fn omit_dev_follows_exact_dependency_target_for_contextual_artifacts() {
    let source = "registry+https://registry.npmjs.org";
    let prod_parent_id =
        lpm_common::PackageInstanceId::derive("prod-parent", "1.0.0", source, "root/prod-parent");
    let dev_plugin_id =
        lpm_common::PackageInstanceId::derive("plugin", "1.0.0", source, "root/dev-parent/plugin");
    let prod_plugin_id =
        lpm_common::PackageInstanceId::derive("plugin", "1.0.0", source, "root/prod-parent/plugin");
    let mut parent = filter_fixture_package("prod-parent", source, Some("prod-parent"), false);
    parent.instance_id = Some(prod_parent_id);
    parent
        .dependencies
        .push(("plugin".to_string(), "1.0.0".to_string()));
    parent
        .dependency_targets
        .insert("plugin".to_string(), prod_plugin_id);
    let mut dev_plugin = filter_fixture_package("plugin", source, None, false);
    dev_plugin.instance_id = Some(dev_plugin_id);
    let mut prod_plugin = dev_plugin.clone();
    prod_plugin.instance_id = Some(prod_plugin_id);
    let mut packages = vec![parent, dev_plugin, prod_plugin];

    filter_dev_packages(&mut packages, &HashSet::from(["prod-parent".to_string()]));

    let retained_plugins = packages
        .iter()
        .filter(|package| package.name == "plugin")
        .map(|package| package.instance_id.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(retained_plugins, vec![prod_plugin_id]);
}

#[test]
fn omit_dev_follows_exact_peer_target_for_contextual_artifacts() {
    let source = "registry+https://registry.npmjs.org";
    let consumer_id =
        lpm_common::PackageInstanceId::derive("consumer", "1.0.0", source, "root/consumer");
    let dev_runtime_id = lpm_common::PackageInstanceId::derive(
        "runtime",
        "1.0.0",
        source,
        "root/dev-parent/runtime",
    );
    let prod_runtime_id =
        lpm_common::PackageInstanceId::derive("runtime", "1.0.0", source, "root/consumer/runtime");
    let mut consumer = filter_fixture_package("consumer", source, Some("consumer"), false);
    consumer.instance_id = Some(consumer_id);
    consumer.peers.push(lpm_common::PeerEdge::registry(
        "runtime", "runtime", "1.0.0",
    ));
    consumer
        .peer_targets
        .insert("runtime".to_string(), prod_runtime_id);
    let mut dev_runtime = filter_fixture_package("runtime", source, None, false);
    dev_runtime.instance_id = Some(dev_runtime_id);
    let mut prod_runtime = dev_runtime.clone();
    prod_runtime.instance_id = Some(prod_runtime_id);
    let mut packages = vec![consumer, dev_runtime, prod_runtime];

    filter_dev_packages(&mut packages, &HashSet::from(["consumer".to_string()]));

    let retained_runtimes = packages
        .iter()
        .filter(|package| package.name == "runtime")
        .map(|package| package.instance_id.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(retained_runtimes, vec![prod_runtime_id]);
}

#[test]
fn optional_filter_restores_ambient_root_to_its_exact_contextual_instance() {
    let source = "registry+https://registry.npmjs.org";
    let first_runtime_id =
        lpm_common::PackageInstanceId::derive("runtime", "1.0.0", source, "root/first-runtime");
    let consumer_id =
        lpm_common::PackageInstanceId::derive("consumer", "1.0.0", source, "root/consumer");
    let ambient_runtime_id =
        lpm_common::PackageInstanceId::derive("runtime", "1.0.0", source, "root/consumer/runtime");
    let mut first_runtime = filter_fixture_package("runtime", source, Some("first-runtime"), false);
    first_runtime.instance_id = Some(first_runtime_id);
    let mut consumer = filter_fixture_package("consumer", source, Some("consumer"), false);
    consumer.instance_id = Some(consumer_id);
    consumer
        .dependencies
        .push(("runtime".to_string(), "1.0.0".to_string()));
    consumer
        .dependency_targets
        .insert("runtime".to_string(), ambient_runtime_id);
    let mut ambient_runtime = filter_fixture_package("runtime", source, Some("runtime"), false);
    ambient_runtime.instance_id = Some(ambient_runtime_id);
    ambient_runtime.is_direct = false;
    let mut packages = vec![first_runtime, consumer, ambient_runtime];

    filter_optional_packages_for_install(&mut packages, &HashSet::new(), &["runtime".to_string()]);

    let first_runtime = packages
        .iter()
        .find(|package| package.instance_id == Some(first_runtime_id))
        .unwrap();
    assert_eq!(
        first_runtime
            .root_link_names
            .as_ref()
            .map(|names| names.iter().map(String::as_str).collect::<Vec<_>>()),
        Some(vec!["first-runtime"])
    );
    let ambient_runtime = packages
        .iter()
        .find(|package| package.instance_id == Some(ambient_runtime_id))
        .unwrap();
    assert_eq!(
        ambient_runtime
            .root_link_names
            .as_ref()
            .map(|names| names.iter().map(String::as_str).collect::<Vec<_>>()),
        Some(vec!["runtime"])
    );
}

// ──.5 lockfile repair gate ─────────────────
//
// The gate's contract:
// - v2+ lockfile (authoritative schema): trust empty
// `ambient-peer-installs` as "no ambient installs."
// - v1 lockfile + `auto_install_peers = true`: discard.
// - v1 lockfile + `auto_install_peers = false`: trust (no
// ambient installs were ever performed under opt-out).
//
// These tests pin the four-way truth table so a future schema
// bump or precedence change can't silently re-open the hole.

fn make_lockfile_with_version(v: u32) -> lpm_lockfile::Lockfile {
    let mut lf = lpm_lockfile::Lockfile::new();
    lf.metadata.lockfile_version = v;
    lf
}

#[test]
fn peer_state_repair_gate_v2_lockfile_with_auto_install_takes_fast_path() {
    // The current happy path: v2 lockfile, auto-install on,
    // schema is authoritative. Don't repair.
    let lf = make_lockfile_with_version(MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE);
    assert!(
        !lockfile_needs_peer_state_repair(&lf, true),
        "virtual-store lockfile with auto-install on must take fast path — \
         empty ambient-peer-installs is authoritative"
    );
}

#[test]
fn peer_state_repair_gate_v1_lockfile_with_auto_install_forces_repair() {
    // The load-bearing test. A v1 lockfile under
    // `auto_install_peers = true` is suspect: it may be missing
    // peer-tracking state. Discard fast path so a
    // fresh resolve repopulates the new fields.
    let lf = make_lockfile_with_version(1);
    assert!(
        lockfile_needs_peer_state_repair(&lf, true),
        "v1 lockfile under auto_install_peers=true must force \
         fresh resolve — the silent ambient-peer-installs hole \
         that cannot be repaired any other way"
    );
}

#[test]
fn peer_state_repair_gate_v1_lockfile_with_auto_install_off_takes_fast_path() {
    // The opt-out path: with `auto_install_peers = false`, no
    // ambient installs were ever performed, so a v1 lockfile is
    // correct as-is. Honor it.
    let lf = make_lockfile_with_version(1);
    assert!(
        !lockfile_needs_peer_state_repair(&lf, false),
        "v1 lockfile under auto_install_peers=false must take \
         fast path — opt-out installs never produced ambient peers"
    );
}

#[test]
fn peer_state_repair_gate_v2_lockfile_with_auto_install_off_takes_fast_path() {
    // Sanity baseline: v2 + opt-out → trust fast path. Symmetric
    // with the v2 + on case above; covered for completeness so
    // no future logic branch can silently invert it.
    let lf = make_lockfile_with_version(MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE);
    assert!(!lockfile_needs_peer_state_repair(&lf, false));
}

#[test]
fn peer_state_repair_gate_rejects_lossy_legacy_peer_strings_even_when_auto_install_is_off() {
    let mut lf =
        make_lockfile_with_version(lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS - 1);
    lf.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "consumer".to_string(),
        version: "1.0.0".to_string(),
        peers: vec!["react@18.2.0".to_string()],
        ..lpm_lockfile::LockedPackage::default()
    });

    assert!(
        lockfile_needs_peer_state_repair(&lf, false),
        "legacy peer strings omit canonical aliases and source identity and cannot be replayed safely"
    );
}

#[test]
fn fresh_lockfiles_use_current_schema_version() {
    assert_eq!(
        lpm_lockfile::LOCKFILE_VERSION,
        lpm_lockfile::LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
    );
    let lf = lpm_lockfile::Lockfile::new();
    assert_eq!(lf.metadata.lockfile_version, lpm_lockfile::LOCKFILE_VERSION);
}

#[test]
fn resolved_to_install_packages_keeps_distinct_versions() {
    // Different versions of the same name must NOT be deduped — only
    // the (canonical_name, version) tuple is the dedup key. Both
    // 5.6.2 and 4.1.2 need their own `.lpm/` store entries.
    let resolved = vec![
        fake_resolved("chalk", "5.6.2", None),
        fake_resolved("chalk", "4.1.2", Some("parent1")),
    ];
    let deps: HashMap<String, String> = [("chalk".to_string(), "^5.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    assert_eq!(installed.len(), 2, "distinct versions must be preserved");
    let mut versions: Vec<String> = installed.iter().map(|p| p.version.clone()).collect();
    versions.sort();
    assert_eq!(versions, vec!["4.1.2".to_string(), "5.6.2".to_string()]);
}

#[test]
fn resolved_to_install_packages_keeps_direct_root_link_when_ambient_peer_has_same_name() {
    let resolved = vec![
        fake_resolved("vite", "6.3.5", None),
        fake_resolved("@vitejs/plugin-react", "1.0.0", None),
        fake_resolved("vite", "8.0.16", Some("@vitejs/plugin-react")),
    ];
    let deps: HashMap<String, String> = [
        ("vite".to_string(), "6.3.5".to_string()),
        ("@vitejs/plugin-react".to_string(), "1.0.0".to_string()),
    ]
    .into();
    let ambient_peer_installs = vec!["vite".to_string()];

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &ambient_peer_installs,
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    let direct = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "6.3.5")
        .expect("direct vite version should be installed");
    assert_eq!(
        direct.root_link_names.as_deref(),
        Some(&["vite".to_string()][..])
    );
    assert!(direct.is_direct);

    let ambient = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "8.0.16")
        .expect("ambient peer vite version should be installed");
    assert_eq!(ambient.root_link_names.as_deref(), None);
    assert!(!ambient.is_direct);
}

#[test]
fn resolved_to_install_packages_prefers_unscoped_root_candidate_for_non_semver_direct_spec() {
    let resolved = vec![
        fake_resolved("vite", "6.3.5", None),
        fake_resolved("@vitejs/plugin-react", "1.0.0", None),
        fake_resolved("vite", "8.0.16", Some("@vitejs/plugin-react")),
    ];
    let deps: HashMap<String, String> = [
        ("vite".to_string(), "file:../local-vite".to_string()),
        ("@vitejs/plugin-react".to_string(), "1.0.0".to_string()),
    ]
    .into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[],
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    let direct = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "6.3.5")
        .expect("unscoped vite candidate should be installed");
    assert_eq!(
        direct.root_link_names.as_deref(),
        Some(&["vite".to_string()][..])
    );
    assert!(direct.is_direct);

    let transitive = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "8.0.16")
        .expect("scoped transitive vite candidate should be installed");
    assert_eq!(transitive.root_link_names.as_deref(), None);
    assert!(!transitive.is_direct);
}

#[test]
fn resolved_to_install_packages_preserves_resolver_order_for_exact_nodes() {
    let resolved = vec![
        fake_resolved("nanoid", "3.3.11", None),
        fake_resolved("nanoid", "3.3.11", Some("parent1")),
        fake_resolved("nanoid", "3.3.11", Some("parent2")),
    ];
    let deps: HashMap<String, String> = [("nanoid".to_string(), "^3.3.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    assert_eq!(installed.len(), 3);
    assert!(installed.iter().all(|package| package.version == "3.3.11"));
    assert_eq!(
        installed
            .iter()
            .map(|package| package.instance_id)
            .collect::<HashSet<_>>()
            .len(),
        3
    );
}

#[test]
fn lockfile_alias_dependencies_are_sorted_by_local_name() {
    let mut resolved = fake_resolved("alias-parent", "1.0.0", None);
    for index in (0..32).rev() {
        let local = format!("local-{index:02}");
        resolved
            .dependencies
            .push((local.clone(), "1.0.0".to_string()));
        resolved.aliases.insert(local, format!("target-{index:02}"));
    }
    let dependencies = HashMap::from([("alias-parent".to_string(), "1.0.0".to_string())]);
    let installed = resolved_to_install_packages(
        &[resolved],
        &dependencies,
        &HashMap::new(),
        &HashMap::new(),
        &[],
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    let locked = locked_package_from_install_package(&installed[0]);
    let local_names: Vec<&str> = locked
        .alias_dependencies
        .iter()
        .map(|alias| alias[0].as_str())
        .collect();
    let mut sorted = local_names.clone();
    sorted.sort_unstable();

    assert_eq!(
        local_names, sorted,
        "lockfile alias mappings must not inherit randomized HashMap iteration order"
    );
}

#[test]
fn locked_root_selection_uses_the_persisted_exact_version() {
    let source = "registry+https://registry.npmjs.org";
    let mut lockfile = lpm_lockfile::Lockfile::new();
    let mut selected_id = None;
    for version in ["1.0.0", "1.1.0"] {
        let instance_id = lpm_common::PackageInstanceId::derive(
            "peer-host",
            version,
            source,
            &format!("root/peer-host/{version}"),
        );
        if version == "1.0.0" {
            selected_id = Some(instance_id);
        }
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: "peer-host".to_string(),
            version: version.to_string(),
            source: Some(source.to_string()),
            ..Default::default()
        });
    }
    lockfile.root_resolutions.insert(
        "peer-host".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: selected_id,
            package: "peer-host".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
        },
    );

    let selected = select_locked_root_package(&lockfile, "peer-host", "peer-host", "^1.0.0")
        .expect("persisted exact root selection");

    assert_eq!(selected.version, "1.0.0");
}

#[test]
fn locked_root_selection_rejects_persisted_version_outside_requested_range() {
    let source = "registry+https://registry.npmjs.org";
    let instance_id =
        lpm_common::PackageInstanceId::derive("test-runner", "1.6.1", source, "root/test-runner");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "test-runner".to_string(),
        version: "1.6.1".to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "test-runner".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: "test-runner".to_string(),
            version: "1.6.1".to_string(),
            source: Some(source.to_string()),
        },
    );

    assert!(
        select_locked_root_package(&lockfile, "test-runner", "test-runner", "^3.2.6").is_none()
    );
}

#[test]
fn locked_root_selection_rejects_git_source_for_registry_specifier() {
    let source =
        "git+https://github.com/attacker/peer-host.git#1111111111111111111111111111111111111111";
    let instance_id =
        lpm_common::PackageInstanceId::derive("peer-host", "1.0.0", source, "root/peer-host");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "peer-host".to_string(),
        version: "1.0.0".to_string(),
        source: Some(source.to_string()),
        integrity: Some(
            "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                .to_string(),
        ),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "peer-host".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: "peer-host".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
        },
    );

    assert!(select_locked_root_package(&lockfile, "peer-host", "peer-host", "1.0.0").is_none());
}

#[test]
fn locked_root_selection_accepts_matching_pinned_github_source() {
    let source =
        "git+https://github.com/example/peer-host.git#1111111111111111111111111111111111111111";
    let instance_id =
        lpm_common::PackageInstanceId::derive("peer-host", "1.0.0", source, "root/peer-host");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "peer-host".to_string(),
        version: "1.0.0".to_string(),
        source: Some(source.to_string()),
        integrity: Some(
            "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                .to_string(),
        ),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "peer-host".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: "peer-host".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
        },
    );

    assert!(
        select_locked_root_package(
            &lockfile,
            "peer-host",
            "peer-host",
            "github:example/peer-host#1111111111111111111111111111111111111111"
        )
        .is_some()
    );
}

#[test]
fn locked_root_selection_rejects_ambiguous_inference_when_exact_selection_is_absent() {
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
    lockfile.root_resolutions.clear();
    for version in ["1.0.0", "1.1.0"] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "peer-host".to_string(),
            version: version.to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            ..Default::default()
        });
    }

    assert!(select_locked_root_package(&lockfile, "peer-host", "peer-host", "^1.0.0").is_none());
}

#[test]
fn current_lockfile_rejects_missing_exact_root_selection() {
    let source = "registry+https://registry.npmjs.org";
    let instance_id =
        lpm_common::PackageInstanceId::derive("peer-host", "1.0.0", source, "root/peer-host");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "peer-host".to_string(),
        version: "1.0.0".to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    });

    assert!(select_locked_root_package(&lockfile, "peer-host", "peer-host", "^1.0.0").is_none());
}

#[test]
fn ambient_root_selection_accepts_exact_workspace_source() {
    let source = "directory+../packages/workspace-lib";
    let instance_id = lpm_common::PackageInstanceId::derive(
        "workspace-lib",
        "1.0.0",
        source,
        "root/workspace-lib",
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "workspace-lib".to_string(),
        version: "1.0.0".to_string(),
        source: Some(source.to_string()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "workspace-lib".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: "workspace-lib".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
        },
    );

    let packages = lockfile.packages.iter().collect::<Vec<_>>();
    let selected =
        select_locked_ambient_root_package_from_rows(&lockfile, &packages, "workspace-lib")
            .expect("exact ambient workspace root");

    assert_eq!(selected.instance_id, Some(instance_id));
    assert_eq!(selected.source.as_deref(), Some(source));
}

#[test]
fn registry_source_url_for_uses_lpm_dev_for_lpm_scope() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    assert_eq!(
        registry_source_url_for("@lpm.dev/foo.bar", &route_table, &RegistryClient::new()),
        "https://lpm.dev"
    );
}

#[test]
fn registry_source_url_for_uses_npmjs_default_for_unscoped() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    assert_eq!(
        registry_source_url_for("react", &route_table, &RegistryClient::new()),
        "https://registry.npmjs.org"
    );
}

#[test]
fn registry_source_url_for_uses_active_client_origins() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = RegistryClient::new()
        .with_base_url("https://lpm.internal.example/api")
        .with_npm_registry_url("https://npm.internal.example");

    assert_eq!(
        registry_source_url_for("@lpm.dev/foo.bar", &route_table, &client),
        "https://lpm.internal.example/api"
    );
    assert_eq!(
        registry_source_url_for("react", &route_table, &client),
        "https://npm.internal.example"
    );
}

#[test]
fn registry_source_url_for_treats_worker_proxy_as_npm_transport() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Proxy);
    let client = RegistryClient::new()
        .with_base_url("https://lpm.internal.example")
        .with_npm_registry_url("https://npm.internal.example");

    assert_eq!(
        registry_source_url_for("react", &route_table, &client),
        "https://npm.internal.example",
        "the Worker proxy and its direct fallback are transports for one logical npm source"
    );
}

#[test]
fn lockfile_fast_path_rejects_registry_source_that_differs_from_active_route() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let lockfile = current_leaf_lockfile("react", "19.0.0", TEST_REGISTRY_SOURCE);
    lockfile.write_to_file(&lockfile_path).unwrap();
    let deps = HashMap::from([("react".to_string(), "19.0.0".to_string())]);
    let client =
        RegistryClient::new().with_npm_registry_url("https://npm.internal.example/registry/");

    let result = try_lockfile_fast_path(
        &lockfile_path,
        &deps,
        &[],
        None,
        &client,
        &GateStats::default(),
        false,
    );

    assert!(result.is_none());
}

#[test]
fn resolved_to_install_packages_uses_lpm_dev_for_lpm_scope() {
    let resolved = vec![fake_resolved("@lpm.dev/foo.bar", "1.0.0", None)];
    let deps: HashMap<String, String> =
        [("@lpm.dev/foo.bar".to_string(), "^1.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].source, "registry+https://lpm.dev");
}

#[test]
fn resolved_to_install_packages_default_npmjs_for_non_lpm_no_npmrc() {
    // Without an `.npmrc` override, non-`@lpm.dev` packages get
    // the npmjs.org default — preserving previously behavior.
    let resolved = vec![fake_resolved("react", "19.0.0", None)];
    let deps: HashMap<String, String> = [("react".to_string(), "^19.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(
        installed[0].source, "registry+https://registry.npmjs.org",
        "no .npmrc override → npmjs.org default"
    );
}

#[test]
fn resolved_to_install_packages_carries_registry_signature_metadata() {
    let signature = lpm_registry::RegistrySignature {
        keyid: Some("SHA256:test-key".to_string()),
        sig: Some("base64-signature".to_string()),
    };
    let dist = lpm_resolver::CachedDistInfo {
        tarball_url: Some("https://registry.npmjs.org/signed/-/signed-1.0.0.tgz".into()),
        integrity: Some(VALID_SHA512_SRI.to_string()),
        unpacked_size: None,
        signatures: vec![signature.clone()],
        published_at: Some("2026-01-02T03:04:05.000Z".to_string()),
        published_at_unix: Some(1_767_323_045),
        trust_evidence: None,
    };
    let mut resolver_cache = HashMap::new();
    resolver_cache.insert(
        lpm_resolver::CanonicalKey::npm("signed"),
        Arc::new(lpm_resolver::CachedPackageInfo::from_manifest_versions(
            None,
            false,
            true,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            true,
            None,
            vec![lpm_resolver::ManifestVersion {
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: Vec::new(),
                peer_dependencies: Vec::new(),
                node_engine: None,
                platform: None,
                dist,
            }],
        )),
    );

    let resolved = vec![fake_resolved("signed", "1.0.0", None)];
    let deps: HashMap<String, String> = [("signed".to_string(), "^1.0.0".to_string())].into();
    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[],
        &resolver_cache,
        RegistrySourceContext::new(
            &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            &RegistryClient::new(),
        ),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].registry_signatures, vec![signature]);
    assert_eq!(
        installed[0].registry_published_at.as_deref(),
        Some("2026-01-02T03:04:05.000Z")
    );
}

#[test]
fn resolved_to_install_packages_uses_npmrc_override_when_present() {
    // The headline reviewed fix: an `.npmrc`-mapped package
    // gets filed under the actual mirror URL, so its source_id
    // distinguishes a mirror copy from an npmjs.org copy.
    use lpm_registry::NpmrcConfig;

    let mirror = "https://npm.internal.example";
    let npmrc_text = format!("registry={mirror}\n");
    let npmrc = NpmrcConfig::parse(&npmrc_text, "test-npmrc", &|_| None);
    let route_table =
        lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();

    let resolved = vec![fake_resolved("react", "19.0.0", None)];
    let deps: HashMap<String, String> = [("react".to_string(), "^19.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        RegistrySourceContext::new(&route_table, &RegistryClient::new()),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(
        installed[0].source,
        format!("registry+{mirror}"),
        ".npmrc default-registry override must reach the InstallPackage source"
    );

    // The corresponding source_id must reflect the mirror URL —
    // proving the motivation now holds end-to-end.
    let mirror_id = lpm_lockfile::Source::Registry {
        url: mirror.to_string(),
    }
    .source_id();
    let npmjs_id = lpm_lockfile::Source::Registry {
        url: "https://registry.npmjs.org".to_string(),
    }
    .source_id();
    assert_ne!(
        mirror_id, npmjs_id,
        "mirror and npmjs source_ids must be distinct (regression check)"
    );
}

// ── lockfile repair and URL gate tests ───────────────────────

#[test]
fn tarball_not_found_error_preserves_project_lockfiles_byte_for_byte() {
    let proj = tempfile::tempdir().unwrap();
    let project_dir = proj.path();

    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    let lock_bytes = b"# existing lockfile\n";
    let lockb_bytes = b"LPMBfake\0bytes";
    std::fs::write(&lock_path, lock_bytes).unwrap();
    std::fs::write(&lockb_path, lockb_bytes).unwrap();

    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let deps = HashMap::from([("some-pkg".to_string(), "1.0.0".to_string())]);
    let packages = resolved_to_install_packages(
        &[fake_resolved("some-pkg", "1.0.0", None)],
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[],
        &HashMap::new(),
        RegistrySourceContext::new(&route_table, &RegistryClient::new()),
    );
    let client = Arc::new(RegistryClient::new());
    let err = artifact_unavailable_error(
        &client,
        &route_table,
        &packages[0],
        ArtifactSelection::LockfileReplay,
    );

    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_bytes,
        "tarball failures must preserve lpm.lock byte-for-byte"
    );
    assert_eq!(
        std::fs::read(&lockb_path).unwrap(),
        lockb_bytes,
        "tarball failures must preserve lpm.lockb byte-for-byte"
    );
    assert!(
        matches!(
            err,
            LpmError::ArtifactUnavailable(ref context)
                if context.package == "some-pkg"
                    && context.version == "1.0.0"
                    && context.lockfiles_preserved
                    && context.suggested_command.as_deref() == Some("lpm upgrade some-pkg")
        ) && err.to_string().contains("pins were preserved"),
        "error must identify the pinned artifact and preserved lockfiles: {err}"
    );
}

#[test]
fn fresh_resolution_artifact_failure_preserves_existing_project_lockfiles() {
    let proj = tempfile::tempdir().unwrap();
    let project_dir = proj.path();

    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    let lock_bytes = b"# stale existing lockfile\n";
    let lockb_bytes = b"LPMBstale-existing";
    std::fs::write(&lock_path, lock_bytes).unwrap();
    std::fs::write(&lockb_path, lockb_bytes).unwrap();

    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let deps = HashMap::from([("overlap-pkg".to_string(), "1.0.0".to_string())]);
    let packages = resolved_to_install_packages(
        &[fake_resolved("overlap-pkg", "1.0.0", None)],
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[],
        &HashMap::new(),
        RegistrySourceContext::new(&route_table, &RegistryClient::new()),
    );
    let client = Arc::new(RegistryClient::new());
    let err = artifact_unavailable_error(
        &client,
        &route_table,
        &packages[0],
        ArtifactSelection::FreshResolution,
    );

    assert_eq!(
        std::fs::read(lock_path).unwrap(),
        lock_bytes,
        "fresh resolution failure must preserve stale lpm.lock byte-for-byte"
    );
    assert_eq!(
        std::fs::read(lockb_path).unwrap(),
        lockb_bytes,
        "fresh resolution failure must preserve stale lpm.lockb byte-for-byte"
    );
    assert!(
        matches!(
            err,
            LpmError::ArtifactUnavailable(ref context)
                if context.kind == lpm_common::ArtifactUnavailableKind::Selected
                    && context.lockfiles_preserved
        ),
        "fresh resolution must retain its own artifact classification: {err}"
    );
}

#[test]
fn artifact_unavailable_error_redacts_registry_credentials_and_url_components() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let deps = HashMap::from([("secret-source".to_string(), "1.0.0".to_string())]);
    let mut packages = resolved_to_install_packages(
        &[fake_resolved("secret-source", "1.0.0", None)],
        &deps,
        &HashMap::new(),
        &HashMap::new(),
        &[],
        &HashMap::new(),
        RegistrySourceContext::new(&route_table, &RegistryClient::new()),
    );
    packages[0].source = "registry+https://user:password@example.test/private/token-value?auth=query-secret#fragment-secret".to_string();

    let err = artifact_unavailable_error(
        &Arc::new(RegistryClient::new()),
        &route_table,
        &packages[0],
        ArtifactSelection::LockfileReplay,
    );
    let rendered = err.to_string();

    assert!(rendered.contains("registry+https://example.test"));
    for secret in [
        "user",
        "password",
        "private",
        "token-value",
        "query-secret",
        "fragment-secret",
    ] {
        assert!(
            !rendered.contains(secret),
            "artifact error exposed secret-bearing URL component {secret:?}: {rendered}"
        );
    }
}

fn locked_directory_package(name: &str, version: &str, path: &str) -> lpm_lockfile::LockedPackage {
    lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: name.to_string(),
        version: version.to_string(),
        source: Some(format!("directory+{path}")),
        integrity: None,
        unpacked_size: None,
        manifest_fingerprint: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: Vec::new(),
        alias_dependencies: Vec::new(),
        peers: Vec::new(),
        peer_edges: Vec::new(),
        tarball: None,
    }
}

#[test]
fn online_lockfile_replay_rejects_workspace_member_identity_substitution() {
    let directory = tempfile::tempdir().expect("create workspace root");
    let expected_path = directory.path().join("packages/expected");
    let substitute_path = directory.path().join("packages/substitute");
    std::fs::create_dir_all(&expected_path).expect("create expected workspace member");
    std::fs::create_dir_all(&substitute_path).expect("create substitute workspace member");
    let workspace = lpm_workspace::Workspace {
        root: directory.path().to_path_buf(),
        root_package: serde_json::from_str(r#"{ "name": "root", "private": true }"#)
            .expect("parse root manifest"),
        members: vec![
            lpm_workspace::WorkspaceMember {
                path: expected_path,
                package: serde_json::from_str(r#"{ "name": "expected", "version": "1.0.0" }"#)
                    .expect("parse expected manifest"),
            },
            lpm_workspace::WorkspaceMember {
                path: substitute_path,
                package: serde_json::from_str(r#"{ "name": "substitute", "version": "1.0.0" }"#)
                    .expect("parse substitute manifest"),
            },
        ],
    };
    let package = locked_directory_package("expected", "1.0.0", "packages/substitute");

    assert!(!online_local_source_is_allowed(
        &package,
        directory.path(),
        &HashMap::new(),
        Some(&workspace),
    ));
}

#[test]
fn online_lockfile_replay_rejects_undeclared_parent_directory_source() {
    let directory = tempfile::tempdir().expect("create project parent");
    let project = directory.path().join("project");
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&outside).expect("create outside package");
    std::fs::write(
        outside.join("package.json"),
        r#"{ "name": "outside", "version": "1.0.0" }"#,
    )
    .expect("write outside manifest");
    let package = locked_directory_package("outside", "1.0.0", "../outside");

    assert!(!online_local_source_is_allowed(
        &package,
        &project,
        &HashMap::new(),
        None,
    ));
}

#[test]
fn offline_lockfile_replay_rejects_undeclared_parent_directory_source() {
    let directory = tempfile::tempdir().expect("create project parent");
    let project = directory.path().join("project");
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&outside).expect("create outside package");
    std::fs::write(
        outside.join("package.json"),
        r#"{ "name": "outside", "version": "1.0.0" }"#,
    )
    .expect("write outside manifest");
    let mut package = locked_directory_package("outside", "1.0.0", "../outside");
    package.manifest_fingerprint = Some(
        read_local_manifest_semantics(&outside)
            .expect("read outside semantics")
            .fingerprint,
    );

    assert!(!online_local_source_is_allowed(
        &package,
        &project,
        &HashMap::new(),
        None,
    ));
}

#[test]
fn online_lockfile_replay_allows_fingerprinted_transitive_local_source_from_reachable_parent() {
    let directory = tempfile::tempdir().expect("create project");
    let parent = directory.path().join("packages/parent");
    let child = directory.path().join("packages/child");
    std::fs::create_dir_all(&parent).expect("create parent package");
    std::fs::create_dir_all(&child).expect("create child package");
    std::fs::write(
        parent.join("package.json"),
        r#"{
          "name": "parent",
          "version": "1.0.0",
          "dependencies": { "child": "file:../child" }
        }"#,
    )
    .expect("write parent manifest");
    std::fs::write(
        child.join("package.json"),
        r#"{ "name": "child", "version": "1.0.0" }"#,
    )
    .expect("write child manifest");
    let mut package = locked_directory_package("child", "1.0.0", "packages/child");
    package.manifest_fingerprint = Some(
        read_local_manifest_semantics(&child)
            .expect("read child semantics")
            .fingerprint,
    );
    let deps = HashMap::from([("parent".to_string(), "file:packages/parent".to_string())]);

    assert!(online_local_source_is_allowed(
        &package,
        directory.path(),
        &deps,
        None,
    ));
}

#[test]
fn binary_writeback_detects_unsupported_binary_version() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let binary_path = dir.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME);

    // Write a valid TOML lockfile with one package matching the
    // single declared root dep.
    let lf = binary_representable_leaf_lockfile("lodash", "4.17.21");
    lf.write_to_file(&lockfile_path).unwrap();

    // Hand-roll a v1 `lpm.lockb` header — just the magic + v1 +
    // zero packages + header-sized string table. `open` rejects
    // with `UnsupportedVersion`, triggering the `needs_binary_upgrade`
    // branch.
    let mut v1_bytes = Vec::with_capacity(16);
    v1_bytes.extend_from_slice(b"LPMB");
    v1_bytes.extend_from_slice(&1u32.to_le_bytes());
    v1_bytes.extend_from_slice(&0u32.to_le_bytes());
    v1_bytes.extend_from_slice(&16u32.to_le_bytes());
    // Write bytes AFTER the TOML so `read_fast` prefers binary
    // (mtime-wise).
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::write(&binary_path, &v1_bytes).unwrap();

    // `read_fast` in the 2nd-round follow-up deletes v1 binaries
    // (`found < BINARY_VERSION`), so by the time `try_lockfile_fast_path`
    // gets to the `BinaryLockfileReader::open` probe, the binary
    // might have been deleted already. Either way,
    // `needs_binary_upgrade` should be true (missing or stale).
    //
    // `try_lockfile_fast_path` loads the lockfile, then probes the
    // binary to decide whether a representable lockfile should be
    // rewritten. The stale v1 file must still trigger the writeback.

    assert!(binary_lockfile_needs_writeback(&lockfile_path, &lf));
}

/// `try_lockfile_fast_path` returns `needs_binary_upgrade = true` when `lpm.lockb` is
/// missing entirely (no binary ever written). Same code path as
/// the v1→v2 migration case but covers fresh projects that
/// ship only the TOML lockfile.
#[test]
fn binary_writeback_ignores_missing_binary_until_a_sidecar_exists() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let lf = binary_representable_leaf_lockfile("lodash", "4.17.21");
    lf.write_to_file(&lockfile_path).unwrap();
    // NO binary file written.

    assert!(binary_lockfile_needs_writeback(&lockfile_path, &lf));
}

#[test]
fn binary_writeback_detects_stale_binary() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let lf = binary_representable_leaf_lockfile("lodash", "4.17.21");
    lf.write_all(&lockfile_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    lf.write_to_file(&lockfile_path).unwrap();

    assert!(binary_lockfile_needs_writeback(&lockfile_path, &lf));
}

#[test]
fn binary_writeback_detects_corrupt_binary() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let binary_path = dir.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME);

    let lf = binary_representable_leaf_lockfile("lodash", "4.17.21");
    lf.write_to_file(&lockfile_path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::write(&binary_path, b"not-a-binary-lockfile").unwrap();

    assert!(binary_lockfile_needs_writeback(&lockfile_path, &lf));
}

/// The writeback trigger skips when the binary is current AND no URL diverged (true happy
/// path). `needs_binary_upgrade` is false when a v2 binary
/// exists and opens cleanly.
#[test]
fn current_v13_fast_path_does_not_require_a_binary_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let lf = current_leaf_lockfile("lodash", "4.17.21", TEST_REGISTRY_SOURCE);
    // `write_all` writes BOTH the TOML and the v2 binary, so the
    // binary is current by construction.
    lf.write_all(&lockfile_path).unwrap();
    assert!(!lockfile_path.with_extension("lockb").exists());

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(
        &lockfile_path,
        &deps,
        &[],
        None,
        &client,
        &gate_stats,
        false,
    )
    .expect("fast path should succeed with both TOML + virtual-store binary");

    assert!(
        !result.needs_binary_upgrade,
        "current virtual-store binary must NOT trigger needs_binary_upgrade"
    );
}

/// Core contract: when the lockfile stores a tarball
/// URL and the gate accepts it, `try_lockfile_fast_path` MUST
/// populate `InstallPackage.tarball_url = Some(url)`. Without
/// this, every warm install still pays the per-package metadata
/// round-trip — i.e., is a no-op.
#[test]
fn accepted_gate_url_populates_tarball_url() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let canonical_url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
    let mut lf = current_leaf_lockfile("lodash", "4.17.21", TEST_REGISTRY_SOURCE);
    let package = lf.packages.first_mut().unwrap();
    *package = lpm_lockfile::LockedPackage {
        instance_id: package.instance_id,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some(TEST_REGISTRY_SOURCE.to_string()),
        integrity: Some(VALID_SHA512_SRI.to_string()),
        unpacked_size: None,
        manifest_fingerprint: None,
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
        peer_edges: Vec::new(),
        tarball: Some(canonical_url.to_string()),
    };
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(
        &lockfile_path,
        &deps,
        &[],
        None,
        &client,
        &gate_stats,
        false,
    )
    .expect("fast path should succeed on valid lockfile");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(
        result.packages[0].tarball_url.as_deref(),
        Some(canonical_url),
        "gate-accepted cached URL must flow into InstallPackage.tarball_url \
         so the fetch pipeline can skip the metadata round-trip"
    );

    use std::sync::atomic::Ordering;
    assert_eq!(gate_stats.origin_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.shape_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.scheme_mismatch.load(Ordering::Relaxed), 0);
}

#[test]
fn try_lockfile_fast_path_restores_registry_signature_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let signature = lpm_lockfile::LockedRegistrySignature {
        keyid: Some("SHA256:test-key".to_string()),
        sig: Some("base64-signature".to_string()),
    };

    let mut lf = current_leaf_lockfile("signed-pkg", "1.0.0", TEST_REGISTRY_SOURCE);
    let package = lf.packages.first_mut().unwrap();
    *package = lpm_lockfile::LockedPackage {
        instance_id: package.instance_id,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "signed-pkg".to_string(),
        version: "1.0.0".to_string(),
        source: Some(TEST_REGISTRY_SOURCE.to_string()),
        integrity: Some(VALID_SHA512_SRI.to_string()),
        unpacked_size: None,
        manifest_fingerprint: None,
        registry_signatures: vec![signature.clone()],
        registry_published_at: Some("2025-01-01T00:00:00.000Z".to_string()),
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        peer_edges: Vec::new(),
        tarball: None,
    };
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("signed-pkg".to_string(), "^1.0.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(
        &lockfile_path,
        &deps,
        &[],
        None,
        &client,
        &gate_stats,
        false,
    )
    .expect("fast path should succeed on signed lockfile");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(
        result.packages[0].registry_signatures,
        vec![lpm_registry::RegistrySignature {
            keyid: signature.keyid,
            sig: signature.sig,
        }]
    );
    assert_eq!(
        result.packages[0].registry_published_at.as_deref(),
        Some("2025-01-01T00:00:00.000Z")
    );
}

/// Complement to the acceptance test: gate-REJECTED URLs must
/// downgrade to `None` AND bump the matching mismatch counter.
/// Three sub-cases: RejectedShape, RejectedOrigin, RejectedScheme.
#[test]
fn rejected_gate_urls_downgrade_to_none_with_telemetry() {
    use std::sync::atomic::Ordering;

    let run_gate = |tarball: &str, client: &RegistryClient| {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        let mut lf = current_leaf_lockfile("victim", "1.0.0", TEST_REGISTRY_SOURCE);
        let package = lf.packages.first_mut().unwrap();
        *package = lpm_lockfile::LockedPackage {
            instance_id: package.instance_id,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "victim".to_string(),
            version: "1.0.0".to_string(),
            source: Some(TEST_REGISTRY_SOURCE.to_string()),
            integrity: Some(VALID_SHA512_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
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
            peer_edges: Vec::new(),
            tarball: Some(tarball.to_string()),
        };
        lf.write_all(&lockfile_path).unwrap();

        let deps: HashMap<String, String> = [("victim".to_string(), "^1.0.0".to_string())].into();
        let gate_stats = GateStats::default();
        let result =
            try_lockfile_fast_path(&lockfile_path, &deps, &[], None, client, &gate_stats, false)
                .expect("fast path should succeed even with a gate-rejected URL");
        (result, gate_stats, dir)
    };

    // (1) RejectedShape — `.tgz` suffix + matching origin +
    // HTTPS, but no `/-/` segment. H1 SSRF defense.
    let client = RegistryClient::new();
    let (result, stats, _dir) = run_gate("https://registry.npmjs.org/api/admin/foo.tgz", &client);
    assert_eq!(result.packages[0].tarball_url, None);
    assert_eq!(stats.shape_mismatch.load(Ordering::Relaxed), 1);
    assert_eq!(stats.origin_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(stats.scheme_mismatch.load(Ordering::Relaxed), 0);

    // (2) RejectedOrigin — canonical shape but origin doesn't
    // match the client's `base_url` / `npm_registry_url`.
    let mirror_client = RegistryClient::new().with_base_url("http://localhost:9999");
    let (result, stats, _dir) = run_gate(
        "https://some-other-mirror.com/foo/-/foo-1.0.0.tgz",
        &mirror_client,
    );
    assert_eq!(result.packages[0].tarball_url, None);
    assert_eq!(stats.origin_mismatch.load(Ordering::Relaxed), 1);
    assert_eq!(stats.shape_mismatch.load(Ordering::Relaxed), 0);

    // (3) RejectedScheme — HTTP (non-localhost) at a matching
    // host is scheme-rejected.
    let (result, stats, _dir) = run_gate(
        "http://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
        &RegistryClient::new(),
    );
    assert_eq!(result.packages[0].tarball_url, None);
    assert_eq!(stats.scheme_mismatch.load(Ordering::Relaxed), 1);
}

fn omit_dev_package(name: &str, source: &str) -> InstallPackage {
    InstallPackage {
        instance_id: None,
        dependency_targets: HashMap::new(),
        peer_targets: HashMap::new(),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: source.to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: false,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        unpacked_size: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
        manifest_fingerprint: None,
    }
}

#[test]
fn omit_dev_retains_exact_local_peer_provider_instead_of_same_coordinate_registry_row() {
    let local_source = "directory+packages/runtime";
    let mut consumer = omit_dev_package("consumer", "registry+https://registry.npmjs.org");
    consumer.root_link_names = Some(vec!["consumer".to_string()]);
    consumer.is_direct = true;
    let registry = omit_dev_package("runtime", "registry+https://registry.npmjs.org");
    let local = omit_dev_package("runtime", local_source);
    let local_wrapper = local.wrapper_id_for_source().unwrap();
    consumer.peers = vec![lpm_common::PeerEdge {
        local_name: "runtime".to_string(),
        target_name: "runtime".to_string(),
        target_version: "1.0.0".to_string(),
        target_wrapper_id: Some(local_wrapper.clone()),
    }];
    let mut packages = vec![consumer, registry, local];

    filter_dev_packages(&mut packages, &HashSet::from(["consumer".to_string()]));

    assert_eq!(packages.len(), 2);
    let retained_provider = packages
        .iter()
        .find(|package| package.name == "runtime")
        .expect("local runtime provider must be retained");
    assert_eq!(
        retained_provider.wrapper_id_for_source().as_deref(),
        Some(local_wrapper.as_str())
    );
    assert_eq!(packages[0].peers[0].target_wrapper_id, Some(local_wrapper));
}

#[test]
fn omit_dev_registry_peer_never_falls_back_to_same_coordinate_local_row() {
    let mut consumer = omit_dev_package("consumer", "registry+https://registry.npmjs.org");
    consumer.root_link_names = Some(vec!["consumer".to_string()]);
    consumer.is_direct = true;
    consumer.peers = vec![lpm_common::PeerEdge::registry(
        "runtime", "runtime", "1.0.0",
    )];
    let local = omit_dev_package("runtime", "directory+packages/runtime");
    let registry = omit_dev_package("runtime", "registry+https://registry.npmjs.org");
    let mut packages = vec![consumer, local, registry];

    filter_dev_packages(&mut packages, &HashSet::from(["consumer".to_string()]));

    assert_eq!(packages.len(), 2);
    let retained_provider = packages
        .iter()
        .find(|package| package.name == "runtime")
        .expect("registry runtime provider must be retained");
    assert!(retained_provider.wrapper_id_for_source().is_none());
}

/// Pre-lockfile shape: `tarball = None`. Fast path
/// must produce `InstallPackage.tarball_url = None` with no
/// counters bumped.
#[test]
fn lockfile_package_without_stored_tarball_has_no_install_url() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let mut lf = current_leaf_lockfile("old-entry", "1.0.0", TEST_REGISTRY_SOURCE);
    let package = lf.packages.first_mut().unwrap();
    *package = lpm_lockfile::LockedPackage {
        instance_id: package.instance_id,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "old-entry".to_string(),
        version: "1.0.0".to_string(),
        source: Some(TEST_REGISTRY_SOURCE.to_string()),
        integrity: Some(VALID_SHA512_SRI.to_string()),
        unpacked_size: None,
        manifest_fingerprint: None,
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
        peer_edges: Vec::new(),
        tarball: None,
    };
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("old-entry".to_string(), "^1.0.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(
        &lockfile_path,
        &deps,
        &[],
        None,
        &client,
        &gate_stats,
        false,
    )
    .expect("fast path should succeed on pre-existing lockfile");

    assert_eq!(result.packages[0].tarball_url, None);

    use std::sync::atomic::Ordering;
    assert_eq!(gate_stats.origin_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.shape_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.scheme_mismatch.load(Ordering::Relaxed), 0);
}
