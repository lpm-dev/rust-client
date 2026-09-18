use super::*;
use serde_json::Value;

mod feature_graph;

fn json_output(project: &TempProject, args: &[&str], directory: Option<&std::path::Path>) -> Value {
    let mut command = lpm(project);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let output = command.args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{args:?}: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn two_package_project(name: &str) -> TempProject {
    let project = TempProject::empty(&serde_json::json!({"name":name,"version":"1.0.0","dependencies":{"react":"1.0.0","unrelated":"1.0.0"}}).to_string());
    write_simple_lockfile(
        &project,
        &[("react", "1.0.0", &[]), ("unrelated", "1.0.0", &[])],
    );
    project
}

#[test]
fn graph_exact_dependency_and_peer_edges_reference_existing_nodes_in_both_orders() {
    for (parent, leaf) in [("a-parent", "z-leaf"), ("z-parent", "a-leaf")] {
        for peer in [false, true] {
            let project = TempProject::empty(&serde_json::json!({"name":"host","version":"1.0.0","dependencies":{parent:"1.0.0",leaf:"1.0.0"}}).to_string());
            let source = "registry+https://registry.npmjs.org";
            let parent_id = lpm_common::PackageInstanceId::derive(parent, "1.0.0", source, parent);
            let leaf_id = lpm_common::PackageInstanceId::derive(leaf, "1.0.0", source, leaf);
            let mut lockfile = lpm_lockfile::Lockfile::new();
            for (name, id) in [(parent, parent_id), (leaf, leaf_id)] {
                let mut package = lpm_lockfile::LockedPackage {
                    name: name.into(),
                    version: "1.0.0".into(),
                    source: Some(source.into()),
                    instance_id: Some(id),
                    ..Default::default()
                };
                if name == parent {
                    if peer {
                        package.peer_targets.insert(leaf.into(), leaf_id);
                        package
                            .peer_edges
                            .push(lpm_common::PeerEdge::registry(leaf, leaf, "1.0.0"));
                    } else {
                        package.dependencies.push(format!("{leaf}@1.0.0"));
                        package.dependency_targets.insert(leaf.into(), leaf_id);
                    }
                }
                lockfile.add_package(package);
                lockfile.root_resolutions.insert(
                    name.into(),
                    lpm_lockfile::LockedRootResolution {
                        instance_id: Some(id),
                        package: name.into(),
                        version: "1.0.0".into(),
                        source: Some(source.into()),
                    },
                );
            }
            project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
            let report = json_output(&project, &["graph", "--format", "json"], None);
            let nodes = report["nodes"].as_array().unwrap();
            let parent_node = nodes.iter().find(|node| node["name"] == parent).unwrap();
            assert_eq!(
                parent_node["deps"],
                serde_json::json!([format!("{leaf}@1.0.0")]),
                "peer={peer}: {report}"
            );
            for edge in report["edges"].as_array().unwrap() {
                assert!(
                    nodes.iter().any(|node| node["key"] == edge["to"]),
                    "{report}"
                );
            }
        }
    }
}

#[test]
fn graph_nested_invocations_use_the_selected_project() {
    for project in [graph_fixture(), workspace_projection_project()] {
        let root = if project.path().join("packages/app").exists() {
            project.path().join("packages/app")
        } else {
            project.path().to_path_buf()
        };
        let nested = root.join("src/nested");
        std::fs::create_dir_all(&nested).unwrap();
        for flags in [
            vec!["graph", "--format", "json"],
            vec!["graph", "--format", "json", "--prod"],
        ] {
            let expected = json_output(&project, &flags, Some(&root));
            let actual = json_output(&project, &flags, Some(&nested));
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn graph_nested_html_writes_to_the_selected_project() {
    let project = graph_fixture();
    let _ = std::fs::remove_file(project.path().join(".lpm/graph.html"));
    let nested = project.path().join("src/nested");
    std::fs::create_dir_all(&nested).unwrap();
    let output = lpm(&project)
        .current_dir(&nested)
        .args(["graph", "--format", "html", "--no-open"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(project.path().join(".lpm/graph.html").is_file());
    assert!(!nested.join(".lpm/graph.html").exists());
}

#[test]
fn graph_accepts_bom_manifests_from_root_and_nested_directories() {
    let project = graph_fixture();
    project.write_file(
        "package.json",
        &format!("\u{feff}{}", project.read_file("package.json")),
    );
    let nested = project.path().join("src");
    std::fs::create_dir_all(&nested).unwrap();
    let root = json_output(&project, &["graph", "--format", "json"], None);
    let nested_report = json_output(&project, &["graph", "--format", "json"], Some(&nested));
    assert_eq!(root, nested_report);
}

#[test]
fn graph_global_json_emits_a_graph_document() {
    let project = two_package_project("host");
    let report = json_output(&project, &["graph", "--json"], None);
    assert_eq!(report["packages"], 2);
    insta::assert_json_snapshot!("graph_global_json", report);
}

#[test]
fn graph_empty_filters_emit_a_graph_document() {
    let project = two_package_project("host");
    let report = json_output(
        &project,
        &["graph", "--format", "json", "--filter", "absent"],
        None,
    );
    assert_eq!(report["packages"], 0);
}

#[test]
fn graph_empty_development_selection_emits_a_graph_document() {
    let project = two_package_project("host");
    let report = json_output(&project, &["graph", "--format", "json", "--dev"], None);
    assert_eq!(report["packages"], 0);
}

#[test]
fn graph_why_explicit_json_emits_a_why_document() {
    let project = two_package_project("host");
    let report = json_output(
        &project,
        &["graph", "--format", "json", "--why", "react"],
        None,
    );
    assert_eq!(report["found"], true);
    assert_eq!(report["path_count"], 1);
}

#[test]
fn graph_rejects_incompatible_output_modes_before_writing_files() {
    let project = two_package_project("host");
    for args in [
        vec!["graph", "--json", "--format", "html", "--no-open"],
        vec!["graph", "--why", "react", "--format", "html", "--no-open"],
        vec!["graph", "--why", "react", "--format", "dot"],
        vec!["graph", "--json", "--format", "mermaid"],
        vec!["graph", "--json", "--format", "stats"],
    ] {
        let output = lpm(&project).args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(!project.path().join(".lpm/graph.html").exists());
    }
}

#[test]
fn graph_registry_attribution_uses_url_hosts() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let cases = [
        ("official-lpm", "registry+https://lpm.dev", "lpm"),
        ("official-npm", "registry+https://registry.npmjs.org", "npm"),
        (
            "fake-npm",
            "registry+https://registry.npmjs.org.example.com",
            "unknown",
        ),
        (
            "fake-lpm",
            "registry+https://example.com/lpm.dev/packages",
            "unknown",
        ),
        (
            "query-npm",
            "registry+https://example.com/?next=npmjs.org",
            "unknown",
        ),
    ];
    let mut lockfile =
        String::from("[metadata]\nlockfile-version = 2\nresolved-with = \"pubgrub\"\n");
    let mut sorted_cases = cases;
    sorted_cases.sort_unstable();
    for (name, source, _) in sorted_cases {
        lockfile.push_str(&format!(
            "\n[[packages]]\nname = {name:?}\nversion = \"1.0.0\"\nsource = {source:?}\n"
        ));
    }
    project.write_file("lpm.lock", &lockfile);
    let report = json_output(&project, &["graph", "--format", "json"], None);
    for (name, _, expected) in cases {
        let node = report["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["name"] == name)
            .unwrap();
        assert_eq!(node["registry"], expected, "{name}: {node}");
    }
}

#[test]
fn graph_filters_include_a_selected_dependency_root() {
    let project = two_package_project("host");
    let report = json_output(
        &project,
        &["graph", "react", "--filter", "react", "--format", "json"],
        None,
    );
    assert_eq!(report["packages"], 1);
    assert_eq!(report["root"], "react@1.0.0");
}

#[test]
fn graph_filters_do_not_match_the_project_name() {
    let project = two_package_project("react-app");
    let report = json_output(
        &project,
        &["graph", "--filter", "react", "--format", "json"],
        None,
    );
    assert_eq!(report["packages"], 1);
    assert!(
        !report["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"] == "unrelated")
    );
}

#[test]
fn graph_why_does_not_count_the_synthetic_project_root() {
    for name in ["host", "react"] {
        let project = two_package_project(name);
        let report = json_output(&project, &["why", name, "--json"], None);
        assert_eq!(report["path_count"], u64::from(name == "react"), "{report}");
        assert_eq!(report["found"], name == "react");
    }
}

#[test]
fn graph_mermaid_assigns_distinct_ids_to_distinct_package_names() {
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"foo-bar":"1.0.0","foo_bar":"1.0.0"}}"#,
    );
    write_simple_lockfile(
        &project,
        &[
            ("foo-bar", "1.0.0", &["foo_bar@1.0.0"]),
            ("foo_bar", "1.0.0", &[]),
        ],
    );
    let output = lpm(&project)
        .args(["graph", "--format", "mermaid"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let ids: std::collections::HashSet<_> = text
        .lines()
        .filter_map(|line| line.split_once("[\"").map(|(id, _)| id.trim()))
        .collect();
    assert_eq!(ids.len(), 3, "{text}");
    for line in text.lines().filter(|line| line.contains(" --> ")) {
        let (from, to) = line.trim().split_once(" --> ").unwrap();
        assert_ne!(from, to, "{text}");
        assert!(ids.contains(from) && ids.contains(to), "{text}");
    }
}

#[test]
fn graph_rejects_non_object_project_manifests() {
    let project = two_package_project("host");
    project.write_file("package.json", "null");
    let output = lpm(&project).args(["graph", "--json"]).output().unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn graph_rejects_fifo_manifests_without_blocking() {
    let project = two_package_project("host");
    let manifest = project.path().join("package.json");
    std::fs::remove_file(&manifest).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&manifest)
            .status()
            .unwrap()
            .success()
    );
    let output = lpm(&project)
        .args(["graph", "--json"])
        .timeout(std::time::Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "graph must reject the FIFO promptly"
    );
}

#[test]
fn graph_unmatched_filter_removes_a_selected_dependency_root() {
    let project = two_package_project("host");
    let report = json_output(
        &project,
        &["graph", "react", "--filter", "absent", "--format", "json"],
        None,
    );
    assert_eq!(report["packages"], 0);
    assert!(report["nodes"].as_array().unwrap().is_empty());
}

#[test]
fn graph_nested_why_keeps_override_and_patch_records() {
    let project = two_package_project("host");
    write_overrides_state(
        &project,
        "fixture",
        &[("react", "1.0.0")],
        &[("react", "0.9.0", "1.0.0", None)],
    );
    write_patch_state(
        &project,
        "fixture",
        &[("react@1.0.0", "react", "1.0.0", "patches/react.patch")],
        &[(
            "react",
            "1.0.0",
            "patches/react.patch",
            &["node_modules/react"],
            1,
            0,
            0,
        )],
    );
    let nested = project.path().join("src");
    std::fs::create_dir_all(&nested).unwrap();
    let expected = json_output(&project, &["why", "react", "--json"], None);
    assert_eq!(expected["applied_overrides"].as_array().unwrap().len(), 1);
    assert_eq!(expected["applied_patches"].as_array().unwrap().len(), 1);
    let actual = json_output(&project, &["why", "react", "--json"], Some(&nested));
    assert_eq!(actual, expected);
}

fn cyclic_filter_project(exact: bool, first: &str, second: &str) -> TempProject {
    let project = TempProject::empty(&serde_json::json!({"name":"host","version":"1.0.0","dependencies":{first:"1.0.0",second:"1.0.0"}}).to_string());
    let mut entries = vec![
        (first, vec![second, "target"]),
        (second, vec![first]),
        ("target", vec![]),
    ];
    entries.sort_unstable_by_key(|(name, _)| *name);
    if exact {
        let source = "registry+https://registry.npmjs.org";
        let ids: std::collections::HashMap<_, _> = entries
            .iter()
            .map(|(name, _)| {
                (
                    *name,
                    lpm_common::PackageInstanceId::derive(name, "1.0.0", source, name),
                )
            })
            .collect();
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for (name, deps) in entries {
            let mut package = lpm_lockfile::LockedPackage {
                name: name.into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                instance_id: Some(ids[name]),
                ..Default::default()
            };
            for dependency in deps {
                package.dependencies.push(format!("{dependency}@1.0.0"));
                package
                    .dependency_targets
                    .insert(dependency.into(), ids[dependency]);
            }
            lockfile.add_package(package);
        }
        for name in [first, second] {
            lockfile.root_resolutions.insert(
                name.into(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(ids[name]),
                    package: name.into(),
                    version: "1.0.0".into(),
                    source: Some(source.into()),
                },
            );
        }
        project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    } else {
        let pins: Vec<_> = entries
            .iter()
            .map(|(_, deps)| {
                deps.iter()
                    .map(|name| format!("{name}@1.0.0"))
                    .collect::<Vec<_>>()
            })
            .collect();
        let borrowed: Vec<Vec<&str>> = pins
            .iter()
            .map(|deps| deps.iter().map(String::as_str).collect())
            .collect();
        let rows: Vec<_> = entries
            .iter()
            .zip(&borrowed)
            .map(|((name, _), deps)| (*name, "1.0.0", deps.as_slice()))
            .collect();
        write_simple_lockfile(&project, &rows);
    }
    project
}

fn assert_cycle_filter_preserves_all_paths(exact: bool) {
    for (first, second) in [("a", "b"), ("b", "a")] {
        let project = cyclic_filter_project(exact, first, second);
        let report = json_output(
            &project,
            &["graph", "--filter", "target", "--format", "json"],
            None,
        );
        assert_eq!(report["packages"], 3, "{report}");
        let why = json_output(
            &project,
            &["graph", "--filter", "target", "--why", "target", "--json"],
            None,
        );
        assert_eq!(why["path_count"], 2, "{why}");
    }
}

#[test]
fn graph_filters_preserve_legacy_paths_through_cycles() {
    assert_cycle_filter_preserves_all_paths(false);
}

#[test]
fn graph_filters_preserve_exact_paths_through_cycles() {
    assert_cycle_filter_preserves_all_paths(true);
}

fn html_visibility(project: &TempProject, package: Option<&str>, collapsed: &[&str]) -> Value {
    let mut command = lpm(project);
    command.args(["graph", "--format", "html", "--no-open"]);
    if let Some(package) = package {
        command.arg(package);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    project.write_file("inspect-graph.cjs", r#"
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.split('<script>')[1].split('</script>')[0];
const element = {style:{},value:'',parentElement:{clientWidth:800,clientHeight:600},addEventListener(){},getContext(){return new Proxy({}, {get(){return function(){};}});}};
const context = {document:{getElementById(){return element;}},window:{devicePixelRatio:1,addEventListener(){}}};
vm.createContext(context);
vm.runInContext(script,context,{timeout:5000});
const visible = () => context.nodes.filter(node=>node._visible).map(node=>node.name).sort();
const initial = visible();
JSON.parse(process.argv[3]).forEach(key=>{context.collapsed[key]=true;});
context.updateVisibleLinks();
process.stdout.write(JSON.stringify({initial,collapsed:visible()}));
"#);
    let output = std::process::Command::new("node")
        .arg(project.path().join("inspect-graph.cjs"))
        .arg(project.path().join(".lpm/graph.html"))
        .arg(serde_json::to_string(collapsed).unwrap())
        .env_remove("NODE_OPTIONS")
        .env("HOME", project.home())
        .output()
        .expect("Node is required to verify exported graph interactions");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn graph_html_collapsing_a_cycle_preserves_visible_roots_and_controls() {
    let project =
        TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{"a":"1.0.0"}}"#);
    write_simple_lockfile(
        &project,
        &[("a", "1.0.0", &["b@1.0.0"]), ("b", "1.0.0", &["a@1.0.0"])],
    );
    let full = html_visibility(&project, None, &["a@1.0.0"]);
    assert_eq!(
        full["initial"],
        serde_json::json!(["a", "b", "host"]),
        "{full}"
    );
    assert_eq!(
        full["collapsed"],
        serde_json::json!(["a", "host"]),
        "{full}"
    );
    let subtree = html_visibility(&project, Some("a"), &["b@1.0.0"]);
    assert_eq!(
        subtree["initial"],
        serde_json::json!(["a", "b"]),
        "{subtree}"
    );
    assert_eq!(
        subtree["collapsed"],
        serde_json::json!(["a", "b"]),
        "{subtree}"
    );
}

#[test]
fn graph_html_collapsing_one_parent_preserves_a_shared_dependency() {
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"a":"1.0.0","b":"1.0.0"}}"#,
    );
    write_simple_lockfile(
        &project,
        &[
            ("a", "1.0.0", &["target@1.0.0"]),
            ("b", "1.0.0", &["target@1.0.0"]),
            ("target", "1.0.0", &[]),
        ],
    );
    let one = html_visibility(&project, None, &["a@1.0.0"]);
    assert_eq!(
        one["collapsed"],
        serde_json::json!(["a", "b", "host", "target"]),
        "{one}"
    );
    let both = html_visibility(&project, None, &["a@1.0.0", "b@1.0.0"]);
    assert_eq!(
        both["collapsed"],
        serde_json::json!(["a", "b", "host"]),
        "{both}"
    );
}
