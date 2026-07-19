use super::*;

// ── invariant: install_root must be the member dir, not workspace ──

#[tokio::test]
async fn run_install_filtered_add_mutates_targeted_member_manifest_on_fresh_workspace() {
    // Regression reproduction: filtered install on a workspace whose root
    // package.json has NO dependencies. Previously this silently dropped
    // the install entirely because run_with_options was called with
    // project_dir=workspace_root, which has empty deps and short-circuits.
    //
    // This test asserts the manifest mutation lands at the targeted
    // member, which is the part of the install pipeline we can verify
    // without network. We can't run the actual install pipeline in
    // unit tests (it needs network), but the manifest mutation is the
    // first step of the workflow and is testable in isolation.
    let dir = tempfile::tempdir().unwrap();
    write_workspace_for_install_tests(
        dir.path(),
        &[
            ("@test/app", "packages/app"),
            ("@test/core", "packages/core"),
        ],
    );

    // Verify the workspace root package.json has NO dependencies
    // (this is the precondition that triggered the bug).
    let root_pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("package.json")).unwrap())
            .unwrap();
    assert!(
        root_pkg.get("dependencies").is_none(),
        "test precondition: workspace root must have no dependencies"
    );

    // Use the install_targets resolver directly — this avoids the
    // network-dependent run_with_options call and verifies the part
    // of the workflow that owns.
    let cwd = dir.path().join("packages").join("core");
    let targets = crate::commands::install_targets::resolve_install_targets(
        &cwd,
        &["@test/app".to_string()],
        &[],
        &[],
        &[],
        false,
        true,
    )
    .unwrap();

    // CRITICAL: install root must be the member dir, not the workspace root
    assert_eq!(targets.member_manifests.len(), 1);
    let install_root =
        crate::commands::install_targets::install_root_for(&targets.member_manifests[0]);
    let expected = dir.path().join("packages").join("app");
    assert_eq!(
        install_root.canonicalize().unwrap(),
        expected.canonicalize().unwrap(),
        "install root for filtered install must be the member dir"
    );
    assert_ne!(
        install_root.canonicalize().unwrap(),
        dir.path().canonicalize().unwrap(),
        "regression: install root must NOT be the workspace root"
    );

    // Now mutate the manifest the way run_install_filtered_add would,
    // and verify the result lands at packages/app. this is
    // the explicit-Exact path, so stage writes the verbatim spec
    // and finalize is a no-op.
    stage_packages_to_manifest(
        &targets.member_manifests[0],
        &["react@18.2.0".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let app_pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("packages/app/package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(app_pkg["dependencies"]["react"], "18.2.0");

    // Workspace root must remain unchanged
    let root_after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("package.json")).unwrap())
            .unwrap();
    assert!(root_after.get("dependencies").is_none());
}

// ── invariant (workspace:^ resolver bug) — diagnostics + repro ──

/// DIAGNOSTIC: empirically confirm what the resolver sees when a member's
/// `package.json` declares a cross-member dep via `workspace:^`. This is
/// the test that distinguished Hypothesis A (rewrite never runs) from
/// Hypothesis B (rewrite runs and turns `workspace:^` into a concrete
/// range that the resolver then fails to fetch from the registry).
///
/// The previously behavior was Hypothesis B: `resolve_workspace_protocol`
/// rewrote `@test/core@workspace:^` to `@test/core@^1.5.0`, the resolver
/// classified `@test/core` as an npm package (it doesn't start with
/// `@lpm.dev/`), and the lookup 404'd against the npm upstream proxy.
///
/// The post-fix behavior is "extracted before resolution": the workspace
/// member is removed from the resolver's input HashMap entirely, and the
/// install pipeline links it directly from its source dir instead.
#[test]
fn workspace_protocol_dep_is_extracted_before_resolver_sees_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Build a workspace where @test/app depends on @test/core via workspace:^
    // and @test/core has a concrete version (1.5.0). Mirrors the user repro.
    let root_pkg = serde_json::json!({
        "name": "monorepo",
        "private": true,
        "workspaces": ["packages/*"],
    });
    std::fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();

    let app_dir = root.join("packages").join("app");
    let core_dir = root.join("packages").join("core");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::create_dir_all(&core_dir).unwrap();

    let app_pkg = serde_json::json!({
        "name": "@test/app",
        "version": "0.1.0",
        "dependencies": { "@test/core": "workspace:^" },
    });
    let core_pkg = serde_json::json!({
        "name": "@test/core",
        "version": "1.5.0",
    });
    std::fs::write(
        app_dir.join("package.json"),
        serde_json::to_string_pretty(&app_pkg).unwrap(),
    )
    .unwrap();
    std::fs::write(
        core_dir.join("package.json"),
        serde_json::to_string_pretty(&core_pkg).unwrap(),
    )
    .unwrap();

    // Reproduce the prefix of run_with_options exactly:
    let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
    let mut deps = pkg.dependencies;
    let workspace = lpm_workspace::discover_workspace(&app_dir)
        .unwrap()
        .unwrap();

    // Previously: deps after `resolve_workspace_protocol` would contain
    // `{"@test/core": "^1.5.0"}` and be passed straight to the resolver,
    // which would call `get_npm_package_metadata("@test/core")` and 404.
    // `extract_workspace_protocol_deps` removes the member from
    // `deps` and returns it as a `WorkspaceMemberLink`.
    let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

    // The resolver-input HashMap must NOT contain @test/core anymore.
    assert!(
        !deps.contains_key("@test/core"),
        "@test/core must be stripped from resolver input instead of \
         being resolved from npm"
    );
    assert!(
        deps.is_empty(),
        "the only declared dep was a workspace member, deps must be empty after extraction"
    );

    // The extracted member metadata must point at the on-disk source dir
    // and the version from the member's own package.json.
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, "@test/core");
    assert_eq!(extracted[0].version, "1.5.0");
    assert_eq!(
        extracted[0].source_dir.canonicalize().unwrap(),
        core_dir.canonicalize().unwrap(),
    );
}

#[test]
fn file_workspace_overlap_is_retained_as_a_direct_v2_source_provider() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("packages/react")).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{
  "name": "workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "peer-consumer": "1.0.0",
    "react": "file:./packages/react"
  }
}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("packages/react/package.json"),
        r#"{"name":"react","version":"18.3.1"}"#,
    )
    .unwrap();

    let package = lpm_workspace::read_package_json(&root.join("package.json")).unwrap();
    let mut deps = package.dependencies.clone();
    let context = prepare_workspace_install_context(root, &package, &mut deps, true, true)
        .expect("workspace context must prepare");

    assert!(
        context
            .direct_workspace_member_deps
            .iter()
            .any(|member| member.name == "react"),
        "file/link workspace overlaps must remain available to v2 source pre-resolution"
    );
    assert!(
        !deps.contains_key("react"),
        "the workspace-backed source must stay out of registry resolution"
    );
}

#[test]
fn file_workspace_overlap_is_retained_with_exact_source_in_v1() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("packages/react")).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{
  "name": "workspace-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "react": "file:./packages/react" }
}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("packages/react/package.json"),
        r#"{"name":"react","version":"18.3.1"}"#,
    )
    .unwrap();

    let package = lpm_workspace::read_package_json(&root.join("package.json")).unwrap();
    let mut deps = package.dependencies.clone();
    let context = prepare_workspace_install_context(root, &package, &mut deps, false, true)
        .expect("workspace context must prepare");

    assert_eq!(context.direct_workspace_member_deps.len(), 1);
    assert_eq!(
        context.direct_workspace_member_deps[0].source,
        "directory+./packages/react"
    );
    let resolved = pre_resolve_v2_direct_workspace_member_deps(
        root,
        &mut deps,
        &context.direct_workspace_member_deps,
        &context.all_workspace_members,
        true,
    )
    .unwrap();
    let providers = explicit_peer_providers_from_install_packages(resolved.install_pkgs.iter())
        .expect("provider classification must succeed");
    let specifier = lpm_resolver::PeerSpecifier::parse("react", "file:./packages/react")
        .expect("peer source must parse");
    assert!(
        providers
            .iter()
            .any(|provider| provider.matches_specifier("react", &specifier)),
        "v1 provider must match the exact file peer source"
    );
}

#[test]
fn workspace_member_cache_info_normalizes_jsr_dependency_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let member_dir = dir.path().join("packages/app");
    std::fs::create_dir_all(&member_dir).unwrap();
    std::fs::write(
        member_dir.join("package.json"),
        r#"{
  "name": "app",
  "version": "1.0.0",
  "dependencies": {
    "@std/path": "jsr:@std/path@1.1.6"
  }
}"#,
    )
    .unwrap();

    let info = workspace_member_cache_info(&WorkspaceMemberLink {
        name: "app".to_string(),
        version: "1.0.0".to_string(),
        source_dir: member_dir,
    })
    .expect("valid jsr dependency should normalize")
    .expect("valid workspace member should produce cache info");

    let deps = info
        .deps
        .get("1.0.0")
        .expect("workspace member version should have dependency metadata");
    assert_eq!(
        deps.get("@std/path").map(String::as_str),
        Some("1.1.6"),
        "JSR dependency must be cached as the npm-alias target range"
    );

    let aliases = info
        .aliases
        .get("1.0.0")
        .expect("workspace member version should have alias metadata");
    assert_eq!(
        aliases.get("@std/path").map(String::as_str),
        Some("@jsr/std__path"),
        "JSR dependency must map the local package name to the npm.jsr.io package"
    );
}

/// `discover_workspace` must walk up from a member dir to the workspace
/// root so `workspace:^` extraction can run.
#[test]
fn discover_workspace_from_member_dir_finds_workspace_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(
        root,
        &[
            ("@test/app", "packages/app"),
            ("@test/core", "packages/core"),
        ],
    );

    // Walking up from any member dir must find the workspace root.
    for member in &["packages/app", "packages/core"] {
        let member_dir = root.join(member);
        let ws = lpm_workspace::discover_workspace(&member_dir)
            .expect("discovery must not error")
            .expect("workspace root must be discoverable from member dir");
        assert_eq!(
            ws.root.canonicalize().unwrap(),
            root.canonicalize().unwrap(),
            "discover_workspace from {member} did not find the workspace root"
        );
    }
}

/// Full extraction round-trip on a workspace where two
/// members reference each other AND the install root has a regular
/// registry dep too. The extraction must:
/// 1. Strip the workspace member dep from `deps`
/// 2. Leave the registry dep in `deps`
/// 3. Return exactly one `WorkspaceMemberLink` pointing at the right dir
#[test]
fn extract_workspace_protocol_deps_only_strips_workspace_protocol_entries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(
        root,
        &[
            ("@test/app", "packages/app"),
            ("@test/core", "packages/core"),
        ],
    );

    // Manually rewrite @test/core's manifest with a real version,
    // and @test/app's manifest with both a registry dep AND a workspace dep.
    std::fs::write(
        root.join("packages/core/package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "@test/core",
            "version": "2.3.4",
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("packages/app/package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "@test/app",
            "version": "0.0.0",
            "dependencies": {
                "@test/core": "workspace:^",
                "react": "^18.0.0",
            },
        }))
        .unwrap(),
    )
    .unwrap();

    let app_dir = root.join("packages/app");
    let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
    let mut deps = pkg.dependencies;
    let workspace = lpm_workspace::discover_workspace(&app_dir)
        .unwrap()
        .unwrap();

    let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

    // Workspace member stripped, registry dep retained.
    assert!(!deps.contains_key("@test/core"));
    assert_eq!(deps.get("react").map(String::as_str), Some("^18.0.0"));
    assert_eq!(deps.len(), 1);

    // Extraction surfaces the member's source dir + version.
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, "@test/core");
    assert_eq!(extracted[0].version, "2.3.4");
    assert_eq!(
        extracted[0].source_dir.canonicalize().unwrap(),
        root.join("packages/core").canonicalize().unwrap(),
    );
}

/// `workspace:` form variants are all handled, not just `workspace:^`.
#[test]
fn extract_workspace_protocol_deps_handles_all_workspace_protocol_forms() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(
        root,
        &[
            ("@test/star", "packages/star"),
            ("@test/caret", "packages/caret"),
            ("@test/tilde", "packages/tilde"),
            ("@test/exact", "packages/exact"),
            ("@test/passthrough", "packages/passthrough"),
            ("@test/host", "packages/host"),
        ],
    );
    // Every member needs a concrete version
    for name in ["star", "caret", "tilde", "exact", "passthrough"] {
        std::fs::write(
            root.join(format!("packages/{name}/package.json")),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": format!("@test/{name}"),
                "version": "1.0.0",
            }))
            .unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        root.join("packages/host/package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "@test/host",
            "version": "0.0.0",
            "dependencies": {
                "@test/star": "workspace:*",
                "@test/caret": "workspace:^",
                "@test/tilde": "workspace:~",
                "@test/exact": "workspace:1.0.0",
                "@test/passthrough": "workspace:>=1.0.0",
            },
        }))
        .unwrap(),
    )
    .unwrap();

    let host_dir = root.join("packages/host");
    let pkg = lpm_workspace::read_package_json(&host_dir.join("package.json")).unwrap();
    let mut deps = pkg.dependencies;
    let workspace = lpm_workspace::discover_workspace(&host_dir)
        .unwrap()
        .unwrap();

    let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

    assert!(
        deps.is_empty(),
        "all five workspace: deps must be stripped, deps={deps:?}"
    );
    assert_eq!(extracted.len(), 5, "all five forms must be extracted");
    let names: std::collections::HashSet<&str> =
        extracted.iter().map(|m| m.name.as_str()).collect();
    for n in [
        "@test/star",
        "@test/caret",
        "@test/tilde",
        "@test/exact",
        "@test/passthrough",
    ] {
        assert!(names.contains(n), "missing extracted member {n}");
    }
}

/// A `workspace:` reference to an unknown member must hard
/// error so users don't silently install nothing. Mirrors the validation
/// `resolve_workspace_protocol` already enforces.
#[test]
fn extract_workspace_protocol_deps_errors_on_unknown_member() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(root, &[("@test/app", "packages/app")]);
    std::fs::write(
        root.join("packages/app/package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "@test/app",
            "version": "0.0.0",
            "dependencies": { "@test/missing": "workspace:^" },
        }))
        .unwrap(),
    )
    .unwrap();

    let app_dir = root.join("packages/app");
    let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
    let mut deps = pkg.dependencies;
    let workspace = lpm_workspace::discover_workspace(&app_dir)
        .unwrap()
        .unwrap();

    let err = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("@test/missing"),
        "error must name the missing member, got: {msg}"
    );
    assert!(
        msg.contains("not a workspace member") || msg.contains("Available"),
        "error must explain what's wrong, got: {msg}"
    );
}

/// When all declared deps are workspace members, the install pipeline
/// must still link them. The empty-deps short-circuit is gated on
/// "deps empty AND workspace member list empty".
#[test]
fn link_workspace_members_creates_node_modules_symlink_to_member_source_dir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(
        root,
        &[
            ("@test/app", "packages/app"),
            ("@test/core", "packages/core"),
        ],
    );
    // Give @test/core a real version
    std::fs::write(
        root.join("packages/core/package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "@test/core",
            "version": "2.0.0",
        }))
        .unwrap(),
    )
    .unwrap();

    let app_dir = root.join("packages/app");
    let core_dir = root.join("packages/core");

    let members = vec![WorkspaceMemberLink {
        name: "@test/core".to_string(),
        version: "2.0.0".to_string(),
        source_dir: core_dir.clone(),
    }];

    let linked = link_workspace_members(&app_dir, &members).unwrap();
    assert_eq!(linked, 1);

    // node_modules/@test/core must exist and resolve back to packages/core
    let link_path = app_dir.join("node_modules").join("@test").join("core");
    assert!(
        link_path.symlink_metadata().is_ok(),
        "expected node_modules/@test/core to exist"
    );
    let resolved = std::fs::canonicalize(&link_path).unwrap();
    assert_eq!(
        resolved,
        core_dir.canonicalize().unwrap(),
        "symlink must resolve to the workspace member's source directory"
    );
}

/// Re-running `link_workspace_members` is idempotent and
/// re-links over a stale symlink. The linker's stale-symlink cleanup
/// pass would otherwise remove our workspace symlinks on every install
/// (they're not in `direct_names`), so the post-link helper has to
/// tolerate "the path already exists from a previous run" gracefully.
#[test]
fn link_workspace_members_is_idempotent_across_repeated_calls() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(
        root,
        &[
            ("@test/app", "packages/app"),
            ("@test/core", "packages/core"),
        ],
    );

    let app_dir = root.join("packages/app");
    let core_dir = root.join("packages/core");

    let members = vec![WorkspaceMemberLink {
        name: "@test/core".to_string(),
        version: "0.0.0".to_string(),
        source_dir: core_dir.clone(),
    }];

    link_workspace_members(&app_dir, &members).unwrap();
    link_workspace_members(&app_dir, &members).unwrap();
    link_workspace_members(&app_dir, &members).unwrap();

    let link_path = app_dir.join("node_modules").join("@test").join("core");
    let resolved = std::fs::canonicalize(&link_path).unwrap();
    assert_eq!(resolved, core_dir.canonicalize().unwrap());
}

#[test]
fn link_workspace_members_from_member_also_populates_workspace_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_workspace_for_install_tests(
        root,
        &[
            ("@test/app", "packages/app"),
            ("@test/core", "packages/core"),
            ("@test/tokens", "packages/tokens"),
        ],
    );

    let app_dir = root.join("packages/app");
    let core_dir = root.join("packages/core");
    let tokens_dir = root.join("packages/tokens");

    let members = vec![
        WorkspaceMemberLink {
            name: "@test/core".to_string(),
            version: "0.0.0".to_string(),
            source_dir: core_dir.clone(),
        },
        WorkspaceMemberLink {
            name: "@test/tokens".to_string(),
            version: "0.0.0".to_string(),
            source_dir: tokens_dir.clone(),
        },
    ];

    link_workspace_members(&app_dir, &members).unwrap();

    let root_core_link = root.join("node_modules").join("@test").join("core");
    let root_tokens_link = root.join("node_modules").join("@test").join("tokens");

    assert_eq!(
        std::fs::canonicalize(&root_core_link).unwrap(),
        core_dir.canonicalize().unwrap(),
        "workspace-root node_modules must expose @test/core for realpath-based transitive imports"
    );
    assert_eq!(
        std::fs::canonicalize(&root_tokens_link).unwrap(),
        tokens_dir.canonicalize().unwrap(),
        "workspace-root node_modules must expose @test/tokens for realpath-based transitive imports"
    );
}

// ────────────────────────────────────────────────────────────────────
// `lpm install` resolves devDependencies.
// `lpm install -D vitest` must land vitest in the manifest and then
// resolve and link it. These tests pin the merge contract used
// right after `let mut deps = pkg.dependencies.clone();`.
// ────────────────────────────────────────────────────────────────────

/// Reproduces the exact merge step that `run_with_options` performs
/// immediately after cloning `pkg.dependencies`. Kept in sync with the
/// inline loop in `run_with_options` — if the production code moves to
/// a helper, point this test at it.
fn merge_dev_dependencies_into_deps(
    deps: &mut HashMap<String, String>,
    dev_deps: &HashMap<String, String>,
) {
    for (name, range) in dev_deps {
        deps.entry(name.clone()).or_insert_with(|| range.clone());
    }
}

#[test]
fn install_merges_dev_dependencies_into_resolver_input() {
    let mut deps: HashMap<String, String> = [("react".to_string(), "^18.0.0".to_string())].into();
    let dev_deps: HashMap<String, String> = [("vitest".to_string(), "^1.0.0".to_string())].into();

    merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

    assert_eq!(deps.len(), 2);
    assert_eq!(deps.get("react").map(String::as_str), Some("^18.0.0"));
    assert_eq!(deps.get("vitest").map(String::as_str), Some("^1.0.0"));
}

#[test]
fn install_merge_lets_dependencies_win_on_conflict() {
    // If the same name appears in both sections, `dependencies` wins.
    // This mirrors the production-contract intuition: devDeps must not
    // shadow the explicit `dependencies` declaration even if someone
    // accidentally adds a second entry.
    let mut deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let dev_deps: HashMap<String, String> = [("lodash".to_string(), "^3.0.0".to_string())].into();

    merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

    assert_eq!(deps.len(), 1);
    assert_eq!(
        deps.get("lodash").map(String::as_str),
        Some("^4.17.0"),
        "dependencies must win over devDependencies on conflict"
    );
}

#[test]
fn install_merge_is_noop_when_dev_dependencies_empty() {
    let mut deps: HashMap<String, String> = [("react".to_string(), "^18.0.0".to_string())].into();
    let original = deps.clone();
    let dev_deps: HashMap<String, String> = HashMap::new();

    merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

    assert_eq!(deps, original);
}

#[test]
fn install_merge_populates_deps_when_only_dev_dependencies_declared() {
    // `lpm install -D vitest` on a project with no regular deps must
    // still produce a non-empty resolver input — this is the exact
    // case the pre-bug silently no-op'd.
    let mut deps: HashMap<String, String> = HashMap::new();
    let dev_deps: HashMap<String, String> = [("vitest".to_string(), "^1.0.0".to_string())].into();

    merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

    assert_eq!(deps.len(), 1);
    assert_eq!(deps.get("vitest").map(String::as_str), Some("^1.0.0"));
}

#[test]
fn install_merge_mirrors_production_call_site_against_live_manifest() {
    // Parse a representative package.json through the same typed reader
    // the install path uses, then run the merge and assert the result.
    // This catches regressions where `pkg.dev_dependencies` stops being
    // parsed (e.g., serde rename drift) — a higher-layer guard than
    // the three HashMap-level tests above.
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    std::fs::write(
        &pkg_path,
        r#"{
            "name": "proj",
            "dependencies": { "react": "^18.0.0" },
            "devDependencies": { "vitest": "^1.0.0", "tsup": "^8.0.0" }
        }"#,
    )
    .unwrap();

    let pkg = lpm_workspace::read_package_json(&pkg_path).unwrap();
    let mut deps = pkg.dependencies.clone();
    merge_dev_dependencies_into_deps(&mut deps, &pkg.dev_dependencies);

    assert_eq!(
        deps.len(),
        3,
        "react + vitest + tsup must all flow into the resolver input"
    );
    assert!(deps.contains_key("react"));
    assert!(deps.contains_key("vitest"));
    assert!(deps.contains_key("tsup"));
}

// ────────────────────────────────────────────────────────────────────
// (): multi-member confirmation prompt.
//
// The bypass tests pin the CI/script-safe paths, and the PTY-backed
// test below exercises the real interactive "decline → abort" branch
// through `stdin.is_terminal()` + `read_line`.
// ────────────────────────────────────────────────────────────────────

#[test]
fn confirm_multi_member_mutation_with_yes_flag_bypasses_prompt() {
    let _lock = confirm_prompt_test_lock();
    let manifests = vec![
        PathBuf::from("/tmp/workspace/packages/a/package.json"),
        PathBuf::from("/tmp/workspace/packages/b/package.json"),
    ];
    let result = confirm_multi_member_mutation("Adding", 1, &manifests, /* yes */ true, false);
    assert!(
        result.is_ok(),
        "--yes must bypass the prompt and return Ok regardless of stdin state"
    );
}

#[test]
fn confirm_multi_member_mutation_in_json_mode_bypasses_prompt() {
    let _lock = confirm_prompt_test_lock();
    let manifests = vec![
        PathBuf::from("/tmp/workspace/packages/a/package.json"),
        PathBuf::from("/tmp/workspace/packages/b/package.json"),
    ];
    let result = confirm_multi_member_mutation(
        "Removing", 2, &manifests, /* yes */ false, /* json_output */ true,
    );
    assert!(
        result.is_ok(),
        "JSON mode must bypass the prompt — agents get a single parseable result"
    );
}

#[test]
fn confirm_multi_member_mutation_with_non_tty_stdin_bypasses_prompt() {
    let _lock = confirm_prompt_test_lock();
    // When tests run under `cargo nextest run`, the process's stdin is
    // piped (NOT a TTY). That alone must bypass the prompt. If this
    // test ever hangs, the non-TTY bypass is broken and would also
    // hang real CI invocations of `lpm install --filter "ui-*"`.
    let manifests = vec![
        PathBuf::from("/tmp/workspace/packages/a/package.json"),
        PathBuf::from("/tmp/workspace/packages/b/package.json"),
    ];
    let result = confirm_multi_member_mutation(
        "Adding", 1, &manifests, /* yes */ false, /* json_output */ false,
    );
    assert!(
        result.is_ok(),
        "non-TTY stdin must bypass the prompt so scripted / CI invocations don't hang. \
         If this test hangs or fails, `is_terminal()` on stdin returned true under test \
         harness and the CI bypass is broken."
    );
}

#[test]
fn confirm_multi_member_mutation_accepts_empty_manifest_list() {
    let _lock = confirm_prompt_test_lock();
    // Defensive: callers only invoke this when `multi_member == true`
    // (length ≥ 2), but the helper must still behave sanely on 0-1
    // entries rather than panicking or over-indexing.
    let empty: Vec<PathBuf> = Vec::new();
    let result = confirm_multi_member_mutation("Adding", 0, &empty, true, false);
    assert!(
        result.is_ok(),
        "empty manifest list with --yes must not error"
    );
}

#[cfg(unix)]
#[test]
fn confirm_multi_member_mutation_decline_on_tty_returns_abort_error() {
    let manifests = vec![
        PathBuf::from("/tmp/workspace/packages/a/package.json"),
        PathBuf::from("/tmp/workspace/packages/b/package.json"),
    ];

    let err = with_tty_stdin_input("n\n", || {
        confirm_multi_member_mutation(
            "Removing", 2, &manifests, /* yes */ false, /* json_output */ false,
        )
        .unwrap_err()
    });

    match err {
        LpmError::Script(message) => {
            assert!(message.contains("aborted by user"));
            assert!(message.contains("no package.json was modified"));
            assert!(message.contains("\"n\""));
        }
        other => panic!("expected Script error, got {other:?}"),
    }
}
