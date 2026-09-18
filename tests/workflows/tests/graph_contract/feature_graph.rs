use super::*;
use lpm_lockfile::{LockedPackage, LockedRootResolution, Lockfile};

const SOURCE: &str = "registry+https://registry.npmjs.org";

fn package(name: &str, version: &str) -> LockedPackage {
    LockedPackage {
        name: name.into(),
        version: version.into(),
        source: Some(SOURCE.into()),
        ..Default::default()
    }
}

fn root(lockfile: &mut Lockfile, local: &str, name: &str, version: &str) {
    lockfile.root_resolutions.insert(
        local.into(),
        LockedRootResolution {
            package: name.into(),
            version: version.into(),
            source: Some(SOURCE.into()),
            ..Default::default()
        },
    );
}

#[test]
fn filtered_graph_recalculates_depth_after_removing_a_shortcut() {
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"a":"1.0.0","shortcut":"1.0.0"}}"#,
    );
    write_simple_lockfile(
        &project,
        &[
            ("a", "1.0.0", &["target@1.0.0"]),
            ("leaf", "1.0.0", &[]),
            ("shortcut", "1.0.0", &["leaf@1.0.0"]),
            ("target", "1.0.0", &["leaf@1.0.0"]),
        ],
    );
    for extra in [vec![], vec!["--depth", "4"]] {
        let mut args = vec!["graph", "--json", "--filter", "target"];
        args.extend(extra);
        let report = json_output(&project, &args, None);
        let nodes = report["nodes"].as_array().unwrap();
        let leaf = nodes.iter().find(|node| node["name"] == "leaf").unwrap();
        assert_eq!(leaf["depth"], 3, "{report}");
        assert_eq!(report["max_depth"], 4);
        assert!(!nodes.iter().any(|node| node["name"] == "shortcut"));
    }
    let report = json_output(
        &project,
        &["graph", "--json", "--filter", "target", "--depth", "3"],
        None,
    );
    assert!(
        !report["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"] == "leaf")
    );
}

#[test]
fn why_json_preserves_distinct_contextual_path_keys() {
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"first":"npm:plugin@1.0.0","second":"npm:plugin@1.0.0"}}"#,
    );
    let mut lockfile = Lockfile::new();
    for slot in ["first", "second"] {
        let id = lpm_common::PackageInstanceId::derive("plugin", "1.0.0", SOURCE, slot);
        let mut plugin = package("plugin", "1.0.0");
        plugin.instance_id = Some(id);
        lockfile.add_package(plugin);
        lockfile.root_aliases.insert(slot.into(), "plugin".into());
        lockfile.root_resolutions.insert(
            slot.into(),
            LockedRootResolution {
                instance_id: Some(id),
                package: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(SOURCE.into()),
            },
        );
    }
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let report = json_output(&project, &["why", "plugin", "--json"], None);
    let graph = json_output(&project, &["graph", "--json"], None);
    assert_eq!(
        report["paths"],
        serde_json::json!([
            ["host@1.0.0", "plugin@1.0.0"],
            ["host@1.0.0", "plugin@1.0.0"]
        ])
    );
    let paths = report["path_keys"]
        .as_array()
        .expect("why must expose exact path keys");
    assert_eq!(paths.len(), 2);
    assert_ne!(paths[0], paths[1]);
    for path in paths {
        let keys = path.as_array().unwrap();
        for key in keys {
            assert!(
                graph["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|node| &node["key"] == key)
            );
        }
        for edge in keys.windows(2) {
            assert!(
                graph["edges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["from"] == edge[0] && entry["to"] == edge[1])
            );
        }
    }
    assert_eq!(
        report,
        json_output(&project, &["graph", "--why", "plugin", "--json"], None)
    );
    assert_eq!(
        report,
        json_output(&project, &["why", "plugin", "--json"], None)
    );
    let absent = json_output(&project, &["why", "absent", "--json"], None);
    assert_eq!(absent["path_keys"], serde_json::json!([]));
}

#[test]
fn legacy_graph_resolves_transitive_alias_edges_to_canonical_nodes() {
    let project = TempProject::empty(r#"{"name":"host","dependencies":{"parent":"1.0.0"}}"#);
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    root(&mut lockfile, "parent", "parent", "1.0.0");
    let mut parent = package("parent", "1.0.0");
    parent.dependencies.push("@local/alias@1.0.0".into());
    parent
        .alias_dependencies
        .push(["@local/alias".into(), "@scope/target".into()]);
    lockfile.add_package(parent);
    lockfile.add_package(package("@scope/target", "1.0.0"));
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let report = json_output(&project, &["graph", "--json"], None);
    let parent = report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "parent")
        .unwrap();
    assert_eq!(parent["deps"], serde_json::json!(["@scope/target@1.0.0"]));
    let why = json_output(&project, &["why", "@scope/target", "--json"], None);
    assert_eq!(why["found"], true);
}

#[test]
fn legacy_graph_recognizes_a_root_alias_without_root_resolutions() {
    let project =
        TempProject::empty(r#"{"name":"host","dependencies":{"local":"npm:target@1.0.0"}}"#);
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 7;
    lockfile.add_package(package("target", "1.0.0"));
    lockfile
        .root_aliases
        .insert("local".into(), "target".into());
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let report = json_output(&project, &["why", "target", "--json"], None);
    assert_eq!(report["found"], true, "{report}");
}

#[test]
fn legacy_graph_uses_the_locked_root_version_and_source() {
    let project = TempProject::empty(r#"{"name":"host","dependencies":{"target":"2.0.0"}}"#);
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    lockfile.add_package(package("target", "1.0.0"));
    lockfile.add_package(package("target", "2.0.0"));
    let mut other_source = package("target", "2.0.0");
    other_source.source = Some("registry+https://registry.example.test".into());
    lockfile.add_package(other_source);
    lockfile.root_resolutions.insert(
        "target".into(),
        LockedRootResolution {
            package: "target".into(),
            version: "2.0.0".into(),
            source: Some(SOURCE.into()),
            ..Default::default()
        },
    );
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let report = json_output(&project, &["graph", "--json"], None);
    let roots: Vec<_> = report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|node| node["is_direct"] == true)
        .collect();
    assert_eq!(roots.len(), 1, "{report}");
    assert_eq!(roots[0]["version"], "2.0.0");
    assert_eq!(roots[0]["registry"], "npm");
}

#[test]
fn legacy_graph_preserves_both_peer_formats() {
    for schema in [11, 12] {
        let project = TempProject::empty(r#"{"name":"host","dependencies":{"plugin":"1.0.0"}}"#);
        let mut lockfile = Lockfile::new();
        lockfile.metadata.lockfile_version = schema;
        root(&mut lockfile, "plugin", "plugin", "1.0.0");
        let mut plugin = package("plugin", "1.0.0");
        if schema == 11 {
            plugin.peers.push("provider@1.0.0".into());
        } else {
            plugin.peer_edges.push(lpm_common::PeerEdge::registry(
                "local-provider",
                "provider",
                "1.0.0",
            ));
        }
        lockfile.add_package(plugin);
        lockfile.add_package(package("provider", "1.0.0"));
        project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
        let report = json_output(&project, &["why", "provider", "--json"], None);
        assert_eq!(report["found"], true, "schema {schema}: {report}");
    }
}

#[test]
fn legacy_graph_rejects_ambiguous_dependency_sources() {
    let project = TempProject::empty(r#"{"name":"host","dependencies":{"parent":"1.0.0"}}"#);
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    root(&mut lockfile, "parent", "parent", "1.0.0");
    let mut parent = package("parent", "1.0.0");
    parent.dependencies.push("target@1.0.0".into());
    lockfile.add_package(parent);
    lockfile.add_package(package("target", "1.0.0"));
    let mut alternative = package("target", "1.0.0");
    alternative.source = Some("registry+https://registry.example.test".into());
    lockfile.add_package(alternative);
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let output = lpm(&project).args(["graph", "--json"]).output().unwrap();
    assert!(
        !output.status.success(),
        "ambiguous graph must not invent exact edges"
    );
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        error["error"].as_str().unwrap().contains("ambiguous"),
        "{error}"
    );
}

#[test]
fn legacy_graph_does_not_apply_dependency_aliases_to_peer_names() {
    let project = TempProject::empty(r#"{"name":"host","dependencies":{"plugin":"1.0.0"}}"#);
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 11;
    root(&mut lockfile, "plugin", "plugin", "1.0.0");
    let mut plugin = package("plugin", "1.0.0");
    plugin.dependencies.push("slot@1.0.0".into());
    plugin
        .alias_dependencies
        .push(["slot".into(), "actual-dep".into()]);
    plugin.peers.push("slot@2.0.0".into());
    lockfile.add_package(plugin);
    lockfile.add_package(package("actual-dep", "1.0.0"));
    lockfile.add_package(package("slot", "2.0.0"));
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let report = json_output(&project, &["graph", "--json"], None);
    let plugin = report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "plugin")
        .unwrap();
    assert_eq!(
        plugin["deps"],
        serde_json::json!(["actual-dep@1.0.0", "slot@2.0.0"])
    );
}

#[test]
fn legacy_graph_does_not_promote_a_skipped_optional_root() {
    let project = TempProject::empty(
        r#"{"name":"host","dependencies":{"parent":"1.0.0"},"optionalDependencies":{"target":"2.0.0"}}"#,
    );
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    root(&mut lockfile, "parent", "parent", "1.0.0");
    let mut parent = package("parent", "1.0.0");
    parent.dependencies.push("target@1.0.0".into());
    lockfile.add_package(parent);
    lockfile.add_package(package("target", "1.0.0"));
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let report = json_output(&project, &["graph", "--json"], None);
    let target = report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "target")
        .unwrap();
    assert_eq!(target["is_direct"], false, "{report}");
    assert_eq!(target["depth"], 2);
}

#[test]
fn legacy_structured_peers_select_the_recorded_source_wrapper() {
    for use_tarball in [false, true] {
        let project = TempProject::empty(r#"{"name":"host","dependencies":{"plugin":"1.0.0"}}"#);
        let mut lockfile = Lockfile::new();
        lockfile.metadata.lockfile_version = 12;
        root(&mut lockfile, "plugin", "plugin", "1.0.0");
        let mut tarball = package("provider", "1.0.0");
        tarball.source = Some("tarball+https://example.test/provider.tgz".into());
        tarball.integrity = Some(
            lpm_common::Integrity::from_bytes(
                lpm_common::integrity::HashAlgorithm::Sha512,
                b"provider",
            )
            .to_string(),
        );
        let mut peer = lpm_common::PeerEdge::registry("local-provider", "provider", "1.0.0");
        if use_tarball {
            peer.target_wrapper_id = Some(tarball.source_kind().unwrap().unwrap().source_id());
        }
        let mut plugin = package("plugin", "1.0.0");
        plugin.peer_edges.push(peer);
        lockfile.add_package(plugin);
        lockfile.add_package(package("provider", "1.0.0"));
        lockfile.add_package(tarball);
        project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
        let graph = json_output(&project, &["graph", "--json"], None);
        let nodes = graph["nodes"].as_array().unwrap();
        let plugin = nodes.iter().find(|node| node["name"] == "plugin").unwrap();
        let deps = plugin["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 1);
        let provider = nodes.iter().find(|node| node["key"] == deps[0]).unwrap();
        assert_eq!(
            provider["registry"],
            if use_tarball { "unknown" } else { "npm" }
        );
    }
}

#[test]
fn legacy_ambiguity_is_checked_before_output_filters() {
    let project = TempProject::empty(
        r#"{"name":"host","dependencies":{"good":"1.0.0"},"devDependencies":{"bad":"1.0.0"}}"#,
    );
    let mut lockfile = Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    for name in ["good", "bad"] {
        root(&mut lockfile, name, name, "1.0.0");
    }
    let mut bad = package("bad", "1.0.0");
    bad.dependencies.push("target@1.0.0".into());
    lockfile.add_package(bad);
    lockfile.add_package(package("good", "1.0.0"));
    lockfile.add_package(package("target", "1.0.0"));
    let mut alternative = package("target", "1.0.0");
    alternative.source = Some("registry+https://other.example.test".into());
    lockfile.add_package(alternative);
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    for args in [
        vec!["graph", "--prod", "--json"],
        vec!["graph", "good", "--json"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(error["error"].as_str().unwrap().contains("ambiguous"));
    }
}
