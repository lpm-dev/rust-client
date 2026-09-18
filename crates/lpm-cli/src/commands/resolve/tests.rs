use super::*;
use lpm_common::ResolutionNodeId;
use lpm_resolver::{NpmVersion, ResolvedPackage, ResolverPackage, RootResolution};
use std::collections::HashSet;

fn node(id: u32, name: &str) -> ResolvedPackage {
    ResolvedPackage {
        resolution_id: ResolutionNodeId::new(id),
        package: ResolverPackage::npm(name),
        version: NpmVersion::parse("1.0.0").unwrap(),
        dependencies: Vec::new(),
        dependency_targets: HashMap::new(),
        optional_dependencies: HashSet::new(),
        aliases: HashMap::new(),
        peers: Vec::new(),
        peer_targets: HashMap::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        node_engine: None,
        optional: false,
    }
}
fn edge(parent: &mut ResolvedPackage, local: &str, target: &ResolvedPackage) {
    parent
        .dependencies
        .push((local.into(), target.version.to_string()));
    parent
        .dependency_targets
        .insert(local.into(), target.resolution_id);
    if local != target.package.canonical_name() {
        parent
            .aliases
            .insert(local.into(), target.package.canonical_name());
    }
}
fn rendered(nodes: &[ResolvedPackage], root_id: u32) -> String {
    let root = nodes
        .iter()
        .find(|p| p.resolution_id.get() == root_id)
        .unwrap();
    let graph = Graph::new(nodes).unwrap();
    let requested = vec![root.package.canonical_name()];
    let root_map = HashMap::from([(
        requested[0].clone(),
        RootResolution {
            target: root.resolution_id,
            package: requested[0].clone(),
            version: root.version.to_string(),
        },
    )]);
    let roots = graph.roots(&requested, &root_map).unwrap();
    let mut output = Vec::new();
    graph
        .render(&roots, &mut output, RenderLimits::default())
        .unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| lpm_common::sanitize_terminal_inline(line).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}
#[test]
fn tree_uses_exact_edge_target_when_two_nodes_share_name_and_version() {
    let mut root = node(0, "root");
    let mut wrong = node(1, "shared");
    let mut correct = node(2, "shared");
    wrong.package = wrong.package.with_context("wrong");
    correct.package = correct.package.with_context("correct");
    let wrong_child = node(3, "wrong-child");
    let right_child = node(4, "right-child");
    edge(&mut wrong, "wrong-child", &wrong_child);
    edge(&mut correct, "right-child", &right_child);
    edge(&mut root, "local", &correct);
    let text = rendered(&[root, wrong, correct, wrong_child, right_child], 0);
    assert!(text.contains("right-child@1.0.0"), "{text}");
    assert!(!text.contains("wrong-child@1.0.0"), "{text}");
    assert!(text.contains("local → shared@1.0.0"), "{text}");
}
#[test]
fn tree_selects_the_exact_requested_root_instance() {
    let mut wrong = node(1, "shared");
    let mut correct = node(2, "shared");
    let wrong_child = node(3, "wrong-child");
    let right_child = node(4, "right-child");
    edge(&mut wrong, "wrong-child", &wrong_child);
    edge(&mut correct, "right-child", &right_child);
    let text = rendered(&[wrong, correct, wrong_child, right_child], 2);
    assert!(text.contains("right-child@1.0.0"), "{text}");
    assert!(!text.contains("wrong-child@1.0.0"), "{text}");
}

fn render_with_limits(
    nodes: &[ResolvedPackage],
    roots: &[(&str, ResolutionNodeId)],
    limits: RenderLimits,
) -> String {
    let graph = Graph::new(nodes).unwrap();
    let mut output = Vec::new();
    graph.render(roots, &mut output, limits).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| lpm_common::sanitize_terminal_inline(line).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tree_distinguishes_true_cycles_from_shared_nodes() {
    let mut root = node(0, "root");
    let mut child = node(1, "child");
    edge(&mut root, "left", &child);
    edge(&mut root, "right", &child);
    edge(&mut child, "root", &root);
    let text = rendered(&[root, child], 0);
    assert_eq!(text.matches("(circular)").count(), 1, "{text}");
    assert_eq!(text.matches("(shared)").count(), 1, "{text}");
}

#[test]
fn dependency_and_aliased_peer_with_the_same_local_name_keep_distinct_targets() {
    let mut root = node(0, "root");
    let dependency = node(1, "dependency");
    let provider = node(2, "peer-provider");
    edge(&mut root, "slot", &dependency);
    root.peer_targets
        .insert("slot".into(), provider.resolution_id);
    root.peers.push(lpm_common::PeerEdge::registry(
        "slot",
        "peer-provider",
        "1.0.0",
    ));
    let nodes = [root, dependency, provider];
    let text = rendered(&nodes, 0);
    assert!(text.contains("slot → dependency@1.0.0"), "{text}");
    assert!(
        text.contains("slot → peer-provider@1.0.0 [#2] (peer)"),
        "{text}"
    );
    let json = Graph::new(&nodes).unwrap().packages_json();
    assert_eq!(json[0]["dependencies"]["slot"], 1);
    assert_eq!(json[0]["peers"]["slot"], 2);
}

#[test]
fn graph_json_uses_canonical_names_and_distinct_ids_for_contexts() {
    let mut first = node(0, "shared");
    let mut second = node(1, "shared");
    first.package = first.package.with_context("first");
    second.package = second.package.with_context("second");
    edge(&mut first, "shared", &second);
    let nodes = [first, second];
    let json = Graph::new(&nodes).unwrap().packages_json();
    assert_eq!(json[0]["package"], "shared");
    assert_eq!(json[1]["package"], "shared");
    assert_ne!(json[0]["id"], json[1]["id"]);
    assert_eq!(json[0]["dependencies"]["shared"], json[1]["id"]);
    assert_eq!(json[0]["context"], "first");
    assert_eq!(json[1]["context"], "second");
}

#[test]
fn graph_rejects_duplicate_ids_and_dangling_explicit_edges() {
    assert!(Graph::new(&[node(0, "a"), node(0, "b")]).is_err());
    let mut root = node(0, "root");
    root.dependency_targets
        .insert("missing".into(), ResolutionNodeId::new(1));
    assert!(Graph::new(&[root]).is_err());
    let mut root = node(0, "root");
    root.peer_targets
        .insert("missing".into(), ResolutionNodeId::new(1));
    assert!(Graph::new(&[root]).is_err());
    let mut root = node(0, "root");
    root.dependencies.push(("missing".into(), "1.0.0".into()));
    assert!(Graph::new(&[root]).is_err());
}

#[test]
fn depth_limited_node_can_expand_from_a_later_shallow_root() {
    let mut root = node(0, "root");
    let mut child = node(1, "child");
    let leaf = node(2, "leaf");
    edge(&mut root, "child", &child);
    edge(&mut child, "leaf", &leaf);
    let text = render_with_limits(
        &[root, child, leaf],
        &[
            ("root", ResolutionNodeId::new(0)),
            ("child", ResolutionNodeId::new(1)),
        ],
        RenderLimits {
            depth: 1,
            ..Default::default()
        },
    );
    assert!(text.contains("(depth limit; use --json)"), "{text}");
    assert!(text.contains("leaf@1.0.0"), "{text}");
}

#[test]
fn row_and_byte_limits_include_a_visible_truncation_marker() {
    let mut root = node(0, "root");
    let children: Vec<_> = (1..30).map(|id| node(id, &format!("child{id}"))).collect();
    for child in &children {
        edge(&mut root, &child.package.canonical_name(), child);
    }
    let mut nodes = vec![root];
    nodes.extend(children);
    for limits in [
        RenderLimits {
            rows: 5,
            ..Default::default()
        },
        RenderLimits {
            bytes: 300,
            ..Default::default()
        },
    ] {
        let (rows, bytes) = (limits.rows, limits.bytes);
        let graph = Graph::new(&nodes).unwrap();
        let mut output = Vec::new();
        graph
            .render(&[("root", ResolutionNodeId::new(0))], &mut output, limits)
            .unwrap();
        assert!(output.len() <= bytes);
        let text = String::from_utf8(output).unwrap();
        assert!(text.lines().count() <= rows);
        assert!(text.contains("tree truncated; use --json"), "{text}");
    }
}

#[test]
fn deep_chain_uses_bounded_depth_without_recursion() {
    let mut nodes: Vec<_> = (0..10_000)
        .map(|id| node(id, &format!("node{id}")))
        .collect();
    for index in 0..nodes.len() - 1 {
        let (before, after) = nodes.split_at_mut(index + 1);
        edge(&mut before[index], &format!("node{}", index + 1), &after[0]);
    }
    let text = rendered(&nodes, 0);
    assert!(text.lines().count() <= 130);
    assert!(text.contains("depth limit"));
}
