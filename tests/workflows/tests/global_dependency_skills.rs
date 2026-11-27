//! Workflow tests for linking the Agent Skills that global packages ship
//! into the home folder's agent folders, as the global skills policy
//! (`lpm skills link --global`) allows, and for keeping those links in step
//! with `install -g`, `global update` and `uninstall -g`. Unix only: the
//! home folder these tests isolate is the one `HOME` names, which Windows
//! doesn't read.
#![cfg(unix)]

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

fn skill_document(name: &str, body: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: Guidance for driving the {name} tool.\n---\n\n# {name}\n\n{body}\n"
    )
}

/// The command a global tool in these tests installs: its name without
/// scope or owner.
fn command_of(name: &str) -> &str {
    name.rsplit(['/', '.']).next().unwrap_or(name)
}

/// A global tool `name@version` with a command of its own and `skills`,
/// each `(directory, SKILL.md)`.
fn tool_package(name: &str, version: &str, skills: &[(&str, String)]) -> Vec<u8> {
    let mut files: Vec<(String, Vec<u8>)> = skills
        .iter()
        .map(|(skill, document)| {
            (
                format!("skills/{skill}/SKILL.md"),
                document.clone().into_bytes(),
            )
        })
        .collect();
    files.push(("cli.js".into(), b"#!/usr/bin/env node\n".to_vec()));
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    make_tarball_from_pkg_json(
        serde_json::json!({ "name": name, "version": version, "bin": { command_of(name): "cli.js" } }),
        &borrowed,
    )
}

/// Serves each of `versions` of `name` from one package document, the last
/// as `latest`.
async fn serve_versions(registry: &MockRegistry, name: &str, versions: &[(&str, Vec<u8>)]) {
    let mut documents = serde_json::Map::new();
    let mut times = serde_json::Map::new();
    for (version, tarball) in versions {
        documents.insert(
            (*version).to_string(),
            serde_json::json!({
                "name": name,
                "version": version,
                "bin": { command_of(name): "cli.js" },
                "dist": {
                    "tarball": registry.tarball_url(name, version),
                    "integrity": compute_integrity(tarball),
                },
            }),
        );
        times.insert(
            (*version).to_string(),
            serde_json::json!("2025-01-01T00:00:00.000Z"),
        );
    }
    let latest = versions.last().expect("at least one version").0;
    let metadata = serde_json::json!({
        "name": name,
        "dist-tags": { "latest": latest },
        "versions": documents,
        "time": times,
    });
    let tarballs: Vec<(&str, Vec<u8>)> = versions
        .iter()
        .map(|(version, tarball)| (*version, tarball.clone()))
        .collect();
    registry
        .with_package_metadata_and_tarballs(name, metadata, &tarballs)
        .await;
}

/// Serves `browser-tool@1.0.0`, which ships the `browser-tool` skill.
async fn serve_browser_tool(registry: &MockRegistry) {
    serve_versions(
        registry,
        "browser-tool",
        &[(
            "1.0.0",
            tool_package(
                "browser-tool",
                "1.0.0",
                &[(
                    "browser-tool",
                    skill_document("browser-tool", "Open the page, then read it."),
                )],
            ),
        )],
    )
    .await;
}

fn run(project: &TempProject, registry: &MockRegistry, args: &[&str]) -> std::process::Output {
    let output = lpm_with_registry(project, &registry.url())
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}: {}", combined(&output));
    output
}

fn run_json(project: &TempProject, registry: &MockRegistry, args: &[&str]) -> serde_json::Value {
    let output = lpm_with_registry(project, &registry.url())
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}: {}", combined(&output));
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{args:?} printed invalid JSON: {error}\n{}",
            combined(&output)
        )
    })
}

fn combined(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The `SKILL.md` linked as `skill` in the home folder's `target`.
fn home_document(project: &TempProject, target: &str, skill: &str) -> Option<String> {
    std::fs::read_to_string(project.home().join(target).join(skill).join("SKILL.md")).ok()
}

fn global_policy_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm/global/skills.json")
}

fn write_global_policy(project: &TempProject, policy: serde_json::Value) {
    let path = global_policy_path(project);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, policy.to_string()).unwrap();
}

fn global_policy(project: &TempProject) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(global_policy_path(project)).unwrap()).unwrap()
}

#[tokio::test]
async fn global_package_skills_link_into_home_agent_folders_only_once_the_global_policy_allows_them()
 {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    std::fs::create_dir(project.home().join(".claude")).unwrap();
    let manifest_before = project.read_file("package.json");

    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_none());

    let preview = run(
        &project,
        &registry,
        &["skills", "link", "--global", "#browser-tool", "--dry-run"],
    );
    assert!(!global_policy_path(&project).exists());
    assert!(
        combined(&preview).contains("allow #browser-tool"),
        "{}",
        combined(&preview)
    );

    let deps = run_json(&project, &registry, &["skills", "deps", "--global"]);
    assert_eq!(deps["global"], true, "{deps:#}");
    assert_eq!(deps["skills"][0]["skill"], "browser-tool", "{deps:#}");
    assert_eq!(deps["skills"][0]["status"], "not_allowed", "{deps:#}");
    assert_eq!(deps["skills"][0]["suggested_selector"], "#browser-tool");
    assert_eq!(
        deps["policy"]["targets"],
        serde_json::json!(["~/.agents/skills", "~/.claude/skills"])
    );

    let report = run_json(
        &project,
        &registry,
        &["skills", "link", "--global", "#browser-tool", "--yes"],
    );
    assert_eq!(
        report["policy_changes"],
        serde_json::json!(["#browser-tool"])
    );
    assert_eq!(
        report["dependency_skills"]["linked"][0]["skill"], "browser-tool",
        "{report:#}"
    );
    assert_eq!(
        report["dependency_skills"]["linked"][0]["targets"],
        serde_json::json!(["~/.agents/skills", "~/.claude/skills"])
    );
    for target in [".agents/skills", ".claude/skills"] {
        let document = home_document(&project, target, "browser-tool")
            .unwrap_or_else(|| panic!("~/{target}/browser-tool is not readable"));
        assert!(document.contains("Open the page, then read it."));
    }
    assert_eq!(
        global_policy(&project),
        serde_json::json!({ "allow": ["#browser-tool"] })
    );
    assert_eq!(project.read_file("package.json"), manifest_before);
    assert!(!project.path().join(".agents").exists());

    let deps = run_json(&project, &registry, &["skills", "deps", "--global"]);
    assert_eq!(deps["skills"][0]["status"], "linked", "{deps:#}");
}

#[tokio::test]
async fn install_g_links_what_the_global_policy_allows_and_uninstall_g_removes_it() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    assert_eq!(
        installed["dependency_skills"]["linked"][0]["skill"], "browser-tool",
        "{installed:#}"
    );
    assert_eq!(
        installed["dependency_skills"]["linked"][0]["targets"],
        serde_json::json!(["~/.agents/skills"])
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());

    let removed = run_json(&project, &registry, &["uninstall", "-g", "browser-tool"]);
    assert_eq!(
        removed["dependency_skills"]["removed"][0]["skill"], "browser-tool",
        "{removed:#}"
    );
    assert!(
        project
            .home()
            .join(".agents/skills/browser-tool")
            .symlink_metadata()
            .is_err()
    );
}

#[tokio::test]
async fn global_update_links_the_skill_the_new_version_ships() {
    let registry = MockRegistry::start().await;
    let release = |version: &str, body: &str| {
        (
            version.to_string(),
            tool_package(
                "browser-tool",
                version,
                &[("browser-tool", skill_document("browser-tool", body))],
            ),
        )
    };
    let versions = [
        release("1.0.0", "First release guidance."),
        release("1.1.0", "Second release guidance."),
    ];
    let versions: Vec<(&str, Vec<u8>)> = versions
        .iter()
        .map(|(version, tarball)| (version.as_str(), tarball.clone()))
        .collect();
    serve_versions(&registry, "browser-tool", &versions).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    assert!(
        home_document(&project, ".agents/skills", "browser-tool")
            .unwrap()
            .contains("First release guidance.")
    );

    let updated = run_json(
        &project,
        &registry,
        &["global", "update", "browser-tool@1.1.0"],
    );

    let change = &updated["dependency_skills"]["updated"][0];
    assert_eq!(change["version"], "1.1.0", "{updated:#}");
    assert_eq!(change["targets"], serde_json::json!(["~/.agents/skills"]));
    assert!(
        home_document(&project, ".agents/skills", "browser-tool")
            .unwrap()
            .contains("Second release guidance.")
    );
}

#[tokio::test]
async fn install_g_with_no_skills_leaves_the_global_links_for_sync_to_catch_up() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));

    run(
        &project,
        &registry,
        &["install", "-g", "--no-skills", "browser-tool@1.0.0"],
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_none());

    let check = lpm_with_registry(&project, &registry.url())
        .args(["skills", "sync", "--global", "--check"])
        .output()
        .unwrap();
    assert!(!check.status.success(), "{}", combined(&check));

    let synced = run(&project, &registry, &["skills", "sync", "--global"]);
    assert!(
        combined(&synced).contains(
            "Linked skill browser-tool from browser-tool@1.0.0 for agents (~/.agents/skills)"
        ),
        "{}",
        combined(&synced)
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );
}

#[tokio::test]
async fn unlink_global_removes_the_entry_and_the_home_links() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());

    let report = run_json(
        &project,
        &registry,
        &["skills", "unlink", "--global", "#browser-tool", "--yes"],
    );

    assert_eq!(
        report["dependency_skills"]["removed"][0]["skill"], "browser-tool",
        "{report:#}"
    );
    assert!(
        !global_policy_path(&project).exists(),
        "an empty global policy leaves no file behind"
    );
    assert!(!project.home().join(".agents/skills/browser-tool").exists());
}

#[tokio::test]
async fn sync_global_check_names_a_missing_home_link_and_sync_restores_it() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    let link = project.home().join(".agents/skills/browser-tool");
    if link.is_dir() && !link.is_symlink() {
        std::fs::remove_dir_all(&link).unwrap();
    } else {
        std::fs::remove_file(&link).unwrap();
    }

    let check = lpm_with_registry(&project, &registry.url())
        .args(["skills", "sync", "--global", "--check"])
        .output()
        .unwrap();

    assert!(!check.status.success(), "{}", combined(&check));
    assert!(
        combined(&check).contains("~/.agents/skills/browser-tool is missing or isn't LPM's link"),
        "{}",
        combined(&check)
    );
    run(&project, &registry, &["skills", "sync", "--global"]);
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );
}

#[tokio::test]
async fn a_global_policy_lpm_cannot_read_links_nothing_and_says_why() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": "#browser-tool" }));

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    assert_eq!(
        installed["dependency_skills"]["linked"],
        serde_json::json!([]),
        "{installed:#}"
    );
    assert_eq!(
        installed["warnings"],
        serde_json::json!(["`allow` in the global skills policy must be an array of selectors"]),
        "{installed:#}"
    );
    assert!(!project.home().join(".agents/skills").exists());
}

#[tokio::test]
async fn skills_list_global_shows_global_links_as_dependency_skills_not_external_ones() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    let listed = run_json(&project, &registry, &["skills", "list", "--global"]);

    assert_eq!(listed["counts"]["dependency"], 1, "{listed:#}");
    assert_eq!(listed["counts"]["external"], 0, "{listed:#}");
    let skill = &listed["skills"]["dependency"][0];
    assert_eq!(skill["scope"], "global");
    assert_eq!(
        skill["links"],
        serde_json::json!(["~/.agents/skills/browser-tool"])
    );
    let project_only = run_json(&project, &registry, &["skills", "list"]);
    assert_eq!(project_only["counts"]["dependency"], 0, "{project_only:#}");
    let viewed = run_json(
        &project,
        &registry,
        &["skills", "view", "--global", "browser-tool"],
    );
    assert_eq!(viewed["kind"], "dependency", "{viewed:#}");
    assert_eq!(viewed["scope"], "global");
}

#[tokio::test]
async fn doctor_global_reports_a_global_link_that_went_missing() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    let healthy = run_json(&project, &registry, &["skills", "doctor", "--global"]);
    assert_eq!(
        healthy["global_dependency_skills"]["healthy"], true,
        "{healthy:#}"
    );
    let link = project.home().join(".agents/skills/browser-tool");
    if link.is_dir() && !link.is_symlink() {
        std::fs::remove_dir_all(&link).unwrap();
    } else {
        std::fs::remove_file(&link).unwrap();
    }

    let report = run_json(&project, &registry, &["skills", "doctor", "--global"]);

    assert_eq!(report["healthy"], false, "{report:#}");
    assert_eq!(
        report["global_dependency_skills"]["issues"],
        serde_json::json!(["~/.agents/skills/browser-tool is missing or isn't LPM's link"])
    );
    let project_only = run_json(&project, &registry, &["skills", "doctor"]);
    assert_eq!(project_only.get("global_dependency_skills"), None);
}

#[tokio::test]
async fn adding_a_global_managed_skill_over_a_global_link_names_the_command_that_unlinks_it() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    project.write_file(
        "team-skills/browser-tool/SKILL.md",
        "---\nname: browser-tool\ndescription: The team's own browser notes\n---\n\nUse the staging browser.\n",
    );

    let output = lpm_with_registry(&project, &registry.url())
        .env_remove("CODEX_HOME")
        .args([
            "skills",
            "add",
            "./team-skills",
            "--skill",
            "browser-tool",
            "--agent",
            "codex",
            "--global",
            "--yes",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", combined(&output));
    assert!(
        combined(&output).contains(
            "linked from the global package browser-tool; run `lpm skills unlink --global '#browser-tool:skill(browser-tool)'` first"
        ),
        "{}",
        combined(&output)
    );
    assert!(
        home_document(&project, ".agents/skills", "browser-tool")
            .unwrap()
            .contains("Open the page, then read it.")
    );
}

#[tokio::test]
async fn a_project_install_neither_reads_nor_changes_the_global_links() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(
        r#"{"name":"app","version":"1.0.0","dependencies":{"browser-tool":"1.0.0"}}"#,
    );
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    run(&project, &registry, &["install"]);

    assert!(!project.path().join(".agents").exists());
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());
    let deps = run_json(&project, &registry, &["skills", "deps"]);
    assert_eq!(deps["skills"][0]["status"], "not_allowed", "{deps:#}");
}

/// Serves the global LPM.dev tool `@lpm.dev/acme.cli@1.0.0` and the
/// registry's reviewed skills for it: one flat skill, `usage`.
async fn serve_lpm_dev_tool(registry: &MockRegistry) {
    serve_lpm_dev_tool_reviewed(registry, serde_json::Value::Null).await;
}

/// [`serve_lpm_dev_tool`], with `usage` served with `warning`, the risks
/// review found, or approved outright when it is null.
async fn serve_lpm_dev_tool_reviewed(registry: &MockRegistry, warning: serde_json::Value) {
    let name = "@lpm.dev/acme.cli";
    serve_versions(
        registry,
        name,
        &[("1.0.0", tool_package(name, "1.0.0", &[]))],
    )
    .await;
    let content = "---\nname: usage\ndescription: How to use it.\n---\nRun acme-cli deploy.\n";
    registry
        .with_package_skills_response(
            "acme.cli",
            serde_json::json!({
                "name": "acme.cli",
                "version": "1.0.0",
                "available": true,
                "skills": [{
                    "name": "usage",
                    "description": "How to use it.",
                    "sizeBytes": content.len(),
                    "rawContent": content,
                    "warning": warning,
                }],
                "skillDirectories": [],
            }),
        )
        .await;
}

#[tokio::test]
async fn a_global_lpm_dev_skill_review_warned_about_links_only_through_an_entry_naming_its_package()
{
    let registry = MockRegistry::start().await;
    serve_lpm_dev_tool_reviewed(
        &registry,
        serde_json::json!([{
            "severity": "high",
            "category": "insecure-patterns",
            "description": "Deploys without asking",
        }]),
    )
    .await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": [":lpm"] }));

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );

    assert!(
        home_document(&project, ".agents/skills", "acme-cli-usage").is_none(),
        "{installed:#}"
    );
    let deps = run_json(&project, &registry, &["skills", "deps", "--global"]);
    let entry = &deps["skills"][0];
    assert_eq!(entry["reason"], "needs_package_name", "{deps:#}");
    assert_eq!(
        entry["review_warning"][0]["description"], "Deploys without asking",
        "{deps:#}"
    );

    run_json(
        &project,
        &registry,
        &["skills", "link", "--global", "#@lpm.dev/acme.cli", "--yes"],
    );

    assert!(home_document(&project, ".agents/skills", "acme-cli-usage").is_some());
}

#[tokio::test]
async fn a_global_lpm_dev_package_reviewed_skills_link_only_through_the_global_policy() {
    let registry = MockRegistry::start().await;
    serve_lpm_dev_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);

    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );
    assert!(!project.home().join(".agents/skills").exists());

    let report = run_json(
        &project,
        &registry,
        &["skills", "link", "--global", "#@lpm.dev/acme.cli", "--yes"],
    );

    assert_eq!(
        report["dependency_skills"]["linked"][0]["skill"], "acme-cli-usage",
        "{report:#}"
    );
    let document = home_document(&project, ".agents/skills", "acme-cli-usage")
        .expect("the reviewed skill is linked");
    assert!(document.contains("name: acme-cli-usage"), "{document}");
    assert!(document.contains("Run acme-cli deploy."), "{document}");
}

#[tokio::test]
async fn install_g_fetches_and_links_the_reviewed_skills_of_an_lpm_dev_package_the_global_policy_allows()
 {
    let registry = MockRegistry::start().await;
    serve_lpm_dev_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(
        &project,
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"] }),
    );

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );

    assert_eq!(
        installed["dependency_skills"]["linked"][0]["skill"], "acme-cli-usage",
        "{installed:#}"
    );
    assert!(
        home_document(&project, ".agents/skills", "acme-cli-usage")
            .unwrap()
            .contains("Run acme-cli deploy.")
    );
}

#[tokio::test]
async fn a_global_manifest_lpm_cannot_read_keeps_the_global_links_and_says_why() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());
    let manifest_path = project.home().join(".lpm/global/manifest.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let newer = manifest.replacen("schema_version = 1", "schema_version = 999", 1);
    assert_ne!(newer, manifest, "the manifest names its schema version");
    std::fs::write(&manifest_path, newer).unwrap();

    let sync = lpm_with_registry(&project, &registry.url())
        .args(["skills", "sync", "--global"])
        .output()
        .unwrap();

    assert!(!sync.status.success(), "{}", combined(&sync));
    assert!(
        combined(&sync).contains("newer than this binary supports"),
        "{}",
        combined(&sync)
    );
    assert!(
        home_document(&project, ".agents/skills", "browser-tool").is_some(),
        "a manifest LPM can't read must not unlink what it lists"
    );
}

#[tokio::test]
async fn link_global_fetches_lpm_dev_reviewed_skills_only_once_the_change_is_confirmed() {
    let registry = MockRegistry::start().await;
    serve_lpm_dev_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );

    let preview = run_json(
        &project,
        &registry,
        &[
            "skills",
            "link",
            "--global",
            "#@lpm.dev/acme.cli",
            "--dry-run",
        ],
    );
    insta::assert_json_snapshot!(
        "global_dependency_skills_link_preview_with_fetches",
        preview
    );
    let human = run(
        &project,
        &registry,
        &[
            "skills",
            "link",
            "--global",
            "#@lpm.dev/acme.cli",
            "--dry-run",
        ],
    );
    assert!(
        combined(&human).contains("fetch the reviewed skills of @lpm.dev/acme.cli@1.0.0"),
        "{}",
        combined(&human)
    );
    let unconfirmed = lpm_with_registry(&project, &registry.url())
        .args(["skills", "link", "--global", "#@lpm.dev/acme.cli"])
        .output()
        .unwrap();
    assert!(!unconfirmed.status.success(), "{}", combined(&unconfirmed));
    assert_eq!(
        registry.package_skills_request_count("acme.cli").await,
        0,
        "neither a dry run nor an unconfirmed change fetches"
    );
    assert!(!global_policy_path(&project).exists());

    let report = run_json(
        &project,
        &registry,
        &["skills", "link", "--global", "#@lpm.dev/acme.cli", "--yes"],
    );

    assert_eq!(
        report["dependency_skills"]["linked"][0]["skill"], "acme-cli-usage",
        "{report:#}"
    );
    assert_eq!(registry.package_skills_request_count("acme.cli").await, 1);
}

#[tokio::test]
async fn sync_global_fetches_the_reviewed_skills_of_an_lpm_dev_package_the_global_policy_allows() {
    let registry = MockRegistry::start().await;
    serve_lpm_dev_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );
    write_global_policy(
        &project,
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"] }),
    );

    let check = lpm_with_registry(&project, &registry.url())
        .args(["skills", "sync", "--global", "--check"])
        .output()
        .unwrap();
    assert!(!check.status.success(), "{}", combined(&check));
    assert!(
        combined(&check).contains(
            "LPM.dev's reviewed skills for @lpm.dev/acme.cli@1.0.0 aren't on this machine yet"
        ),
        "{}",
        combined(&check)
    );
    assert_eq!(registry.package_skills_request_count("acme.cli").await, 0);

    let report = run_json(&project, &registry, &["skills", "sync", "--global"]);

    assert_eq!(
        report["dependency_skills"]["linked"][0]["skill"], "acme-cli-usage",
        "{report:#}"
    );
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );
}

/// Makes `path` unreadable until dropped.
struct Sealed(std::path::PathBuf);

impl Sealed {
    fn new(path: std::path::PathBuf) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        Self(path)
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// The folder the only installed global package lives in.
fn only_install_root(project: &TempProject) -> std::path::PathBuf {
    let mut roots: Vec<_> = std::fs::read_dir(project.home().join(".lpm/global/installs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(roots.len(), 1, "{roots:?}");
    roots.pop().unwrap()
}

#[tokio::test]
async fn unlink_global_all_never_denies_an_lpm_dev_global_package_whose_install_cannot_be_read() {
    // SAFETY: geteuid has no preconditions. Root ignores the modes below.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let registry = MockRegistry::start().await;
    serve_lpm_dev_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(
        &project,
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"] }),
    );
    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );
    assert!(home_document(&project, ".agents/skills", "acme-cli-usage").is_some());

    let (unlinked, deps) = {
        let _sealed = Sealed::new(only_install_root(&project).join("node_modules"));
        (
            run_json(
                &project,
                &registry,
                &["skills", "unlink", "--global", "--all", "--yes"],
            ),
            run_json(&project, &registry, &["skills", "deps", "--global"]),
        )
    };

    assert!(
        deps["unlisted"].to_string().contains("@lpm.dev/acme.cli"),
        "{deps:#}"
    );
    assert_eq!(
        unlinked["denied"],
        serde_json::json!([]),
        "a global LPM.dev package links only through an allowing entry: {unlinked:#}"
    );
    assert!(home_document(&project, ".agents/skills", "acme-cli-usage").is_none());
}

#[tokio::test]
async fn list_global_agent_finds_a_global_link_in_that_agents_home_folder() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(
        &project,
        serde_json::json!({ "allow": ["#browser-tool"], "targets": [".pi/agent/skills"] }),
    );
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    assert!(home_document(&project, ".pi/agent/skills", "browser-tool").is_some());

    let output = lpm_with_registry(&project, &registry.url())
        .env_remove("PI_CODING_AGENT_DIR")
        .args(["--json", "skills", "list", "--global", "--agent", "pi"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", combined(&output));
    let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed["counts"]["dependency"], 1, "{listed:#}");
    assert_eq!(
        listed["skills"]["dependency"][0]["links"],
        serde_json::json!(["~/.pi/agent/skills/browser-tool"])
    );
}

#[tokio::test]
async fn deps_global_labels_each_skills_links_under_the_home_folder() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    let deps = run_json(&project, &registry, &["skills", "deps", "--global"]);

    assert_eq!(
        deps["skills"][0]["links"],
        serde_json::json!(["~/.agents/skills/browser-tool"]),
        "{deps:#}"
    );
}

#[tokio::test]
async fn view_global_shows_the_global_copy_of_a_skill_the_project_links_too() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(
        r##"{"name":"app","version":"1.0.0","dependencies":{"browser-tool":"1.0.0"},"lpm":{"skills":{"allow":["#browser-tool"]}}}"##,
    );
    run(&project, &registry, &["install"]);
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    let global = run_json(
        &project,
        &registry,
        &["skills", "view", "--global", "browser-tool"],
    );
    let local = run_json(&project, &registry, &["skills", "view", "browser-tool"]);

    assert_eq!(global["scope"], "global", "{global:#}");
    assert_eq!(
        global["links"],
        serde_json::json!(["~/.agents/skills/browser-tool"])
    );
    assert_eq!(local["scope"], "project", "{local:#}");
}

#[tokio::test]
async fn global_dependency_skill_commands_have_stable_json_envelopes() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    let deps = run_json(&project, &registry, &["skills", "deps", "--global"]);
    insta::assert_json_snapshot!("global_dependency_skills_deps", deps);

    let link_preview = run_json(
        &project,
        &registry,
        &["skills", "link", "--global", "#browser-tool", "--dry-run"],
    );
    insta::assert_json_snapshot!("global_dependency_skills_link_preview", link_preview);

    let link = run_json(
        &project,
        &registry,
        &["skills", "link", "--global", "#browser-tool", "--yes"],
    );
    insta::assert_json_snapshot!("global_dependency_skills_link_applied", link);

    let sync = run_json(&project, &registry, &["skills", "sync", "--global"]);
    insta::assert_json_snapshot!("global_dependency_skills_sync_unchanged", sync);

    let link_path = project.home().join(".agents/skills/browser-tool");
    std::fs::remove_file(&link_path).unwrap();
    let check = lpm_with_registry(&project, &registry.url())
        .args(["--json", "skills", "sync", "--global", "--check"])
        .output()
        .unwrap();
    assert!(!check.status.success());
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    insta::assert_json_snapshot!("global_dependency_skills_sync_check_drift", check);
    run_json(&project, &registry, &["skills", "sync", "--global"]);

    let unlink_preview = run_json(
        &project,
        &registry,
        &["skills", "unlink", "--global", "#browser-tool", "--dry-run"],
    );
    insta::assert_json_snapshot!("global_dependency_skills_unlink_preview", unlink_preview);

    let unlink = run_json(
        &project,
        &registry,
        &["skills", "unlink", "--global", "#browser-tool", "--yes"],
    );
    insta::assert_json_snapshot!("global_dependency_skills_unlink_applied", unlink);

    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run_json(&project, &registry, &["uninstall", "-g", "browser-tool"]);
    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    insta::assert_json_snapshot!(
        "global_dependency_skills_install_g_report",
        installed["dependency_skills"]
    );
    let uninstalled_again = run_json(&project, &registry, &["uninstall", "-g", "browser-tool"]);
    insta::assert_json_snapshot!(
        "global_dependency_skills_uninstall_g_report",
        uninstalled_again["dependency_skills"]
    );
}

#[tokio::test]
async fn global_links_follow_a_link_the_user_made_to_an_agent_folder() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    let dotfiles = project.home().join("dotfiles/claude");
    std::fs::create_dir_all(&dotfiles).unwrap();
    std::os::unix::fs::symlink(&dotfiles, project.home().join(".claude")).unwrap();
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    assert_eq!(
        installed["dependency_skills"]["linked"][0]["targets"],
        serde_json::json!(["~/.agents/skills", "~/.claude/skills"]),
        "{installed:#}"
    );
    assert!(dotfiles.join("skills/browser-tool/SKILL.md").is_file());
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );

    let unlinked = run_json(
        &project,
        &registry,
        &["skills", "unlink", "--global", "#browser-tool", "--yes"],
    );

    assert_eq!(
        unlinked["dependency_skills"]["removed"][0]["targets"],
        serde_json::json!(["~/.agents/skills", "~/.claude/skills"]),
        "{unlinked:#}"
    );
    assert!(!dotfiles.join("skills/browser-tool").exists());
    assert!(dotfiles.is_dir(), "the user's folder stays");
}

#[tokio::test]
async fn a_home_skills_folder_linked_to_another_target_gets_each_skill_once() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".agents/skills")).unwrap();
    std::fs::create_dir_all(project.home().join(".claude")).unwrap();
    std::os::unix::fs::symlink(
        project.home().join(".agents/skills"),
        project.home().join(".claude/skills"),
    )
    .unwrap();
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    assert_eq!(
        installed["dependency_skills"]["linked"][0]["targets"],
        serde_json::json!(["~/.agents/skills"]),
        "{installed:#}"
    );
    assert_eq!(
        installed["warnings"],
        serde_json::Value::Null,
        "{installed:#}"
    );
    assert!(home_document(&project, ".claude/skills", "browser-tool").is_some());
}

#[tokio::test]
async fn the_global_policy_is_never_written_through_a_linked_global_folder() {
    let registry = MockRegistry::start().await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    let elsewhere = project.home().join("disk/lpm-global");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::create_dir_all(project.home().join(".lpm")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, project.home().join(".lpm/global")).unwrap();

    let link = lpm_with_registry(&project, &registry.url())
        .args(["skills", "link", "--global", "#browser-tool", "--yes"])
        .output()
        .unwrap();

    assert!(!link.status.success(), "{}", combined(&link));
    assert!(
        combined(&link).contains("open without following filesystem links"),
        "{}",
        combined(&link)
    );
    assert!(!elsewhere.join("skills.json").exists());
}

#[tokio::test]
async fn consolidating_two_home_skills_folders_into_one_keeps_the_skill_linked() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".claude")).unwrap();
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );
    let claude_skills = project.home().join(".claude/skills");
    std::fs::remove_file(claude_skills.join("browser-tool")).unwrap();
    std::fs::remove_dir(&claude_skills).unwrap();
    std::os::unix::fs::symlink(project.home().join(".agents/skills"), &claude_skills).unwrap();

    let synced = run_json(&project, &registry, &["skills", "sync", "--global"]);

    assert!(
        home_document(&project, ".agents/skills", "browser-tool").is_some(),
        "{synced:#}"
    );
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );
}

#[tokio::test]
async fn a_home_skills_folder_linked_before_its_destination_exists_is_linked_once() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".claude")).unwrap();
    std::os::unix::fs::symlink(
        project.home().join(".agents/skills"),
        project.home().join(".claude/skills"),
    )
    .unwrap();
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));

    let installed = run_json(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    assert_eq!(
        installed["dependency_skills"]["linked"][0]["targets"],
        serde_json::json!(["~/.agents/skills"]),
        "{installed:#}"
    );
    assert_eq!(
        installed["warnings"],
        serde_json::Value::Null,
        "{installed:#}"
    );
    let synced = run_json(&project, &registry, &["skills", "sync", "--global"]);
    assert_eq!(
        synced["dependency_skills"]["removed"],
        serde_json::json!([]),
        "{synced:#}"
    );
    assert!(home_document(&project, ".agents/skills", "browser-tool").is_some());
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );
}

#[tokio::test]
async fn a_global_policy_changed_while_its_sets_are_fetched_writes_neither_the_policy_nor_the_sets()
{
    let registry = MockRegistry::start().await;
    let name = "@lpm.dev/acme.cli";
    serve_versions(
        &registry,
        name,
        &[("1.0.0", tool_package(name, "1.0.0", &[]))],
    )
    .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/registry/skills"))
        .and(wiremock::matchers::query_param("name", "acme.cli"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "name": "acme.cli",
                    "version": "1.0.0",
                    "available": true,
                    "skills": [],
                    "skillDirectories": [],
                }))
                .set_delay(std::time::Duration::from_secs(2)),
        )
        .mount(registry.server())
        .await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );
    let mut link = lpm_with_registry(&project, &registry.url());
    link.args(["skills", "link", "--global", "#@lpm.dev/acme.cli", "--yes"]);
    let linking = tokio::task::spawn_blocking(move || link.output().unwrap());

    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    write_global_policy(&project, serde_json::json!({ "allow": ["#other"] }));
    let linked = linking.await.unwrap();

    assert!(!linked.status.success(), "{}", combined(&linked));
    assert!(
        combined(&linked).contains("changed while its skills policy was being edited"),
        "{}",
        combined(&linked)
    );
    assert_eq!(
        global_policy(&project),
        serde_json::json!({ "allow": ["#other"] })
    );
    assert!(
        !only_install_root(&project).join(".lpm/skills").exists(),
        "no fetched set lands once the change is refused"
    );
}

#[tokio::test]
async fn a_global_policy_that_can_link_nothing_from_a_package_fetches_nothing_for_it() {
    let registry = MockRegistry::start().await;
    let name = "@lpm.dev/acme.cli";
    serve_versions(
        &registry,
        name,
        &[("1.0.0", tool_package(name, "1.0.0", &[]))],
    )
    .await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );

    for policy in [
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"], "deny": ["#@lpm.dev/acme.cli"] }),
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"], "deny": ["#("] }),
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"], "deny": ["#@lpm.dev/acme.cli@1.0.0"] }),
    ] {
        write_global_policy(&project, policy.clone());

        let check = lpm_with_registry(&project, &registry.url())
            .args(["skills", "sync", "--global", "--check"])
            .output()
            .unwrap();
        let output = combined(&check);
        assert!(
            !output.contains("aren't on this machine yet"),
            "{policy}: {output}"
        );
        lpm_with_registry(&project, &registry.url())
            .args(["skills", "sync", "--global"])
            .output()
            .unwrap();
    }

    assert_eq!(registry.package_skills_request_count("acme.cli").await, 0);
}

#[tokio::test]
async fn a_set_lpm_dev_refused_is_asked_for_once_and_then_leaves_the_check_clean() {
    let registry = MockRegistry::start().await;
    let name = "@lpm.dev/acme.cli";
    serve_versions(
        &registry,
        name,
        &[("1.0.0", tool_package(name, "1.0.0", &[]))],
    )
    .await;
    registry
        .with_package_skills_response(
            "acme.cli",
            serde_json::json!({
                "name": "acme.cli",
                "version": "1.0.0",
                "available": false,
                "skillsCount": 1,
                "skillsStatus": "rejected",
                "skills": [],
            }),
        )
        .await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    run(
        &project,
        &registry,
        &["install", "-g", "@lpm.dev/acme.cli@1.0.0"],
    );
    write_global_policy(
        &project,
        serde_json::json!({ "allow": ["#@lpm.dev/acme.cli"] }),
    );

    let synced = run_json(&project, &registry, &["skills", "sync", "--global"]);

    assert!(
        synced["warnings"]
            .to_string()
            .contains("were rejected by security review"),
        "{synced:#}"
    );
    run(
        &project,
        &registry,
        &["skills", "sync", "--global", "--check"],
    );
    run_json(&project, &registry, &["skills", "sync", "--global"]);
    assert_eq!(registry.package_skills_request_count("acme.cli").await, 1);
}

#[tokio::test]
async fn a_skill_in_a_home_folder_two_agents_share_lists_for_both_and_never_as_external() {
    let registry = MockRegistry::start().await;
    serve_browser_tool(&registry).await;
    let project = TempProject::empty(r#"{"name":"app","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".agents/skills")).unwrap();
    std::fs::create_dir_all(project.home().join(".claude")).unwrap();
    std::os::unix::fs::symlink(
        project.home().join(".agents/skills"),
        project.home().join(".claude/skills"),
    )
    .unwrap();
    write_global_policy(&project, serde_json::json!({ "allow": ["#browser-tool"] }));
    run(
        &project,
        &registry,
        &["install", "-g", "browser-tool@1.0.0"],
    );

    let claude = run_json(
        &project,
        &registry,
        &["skills", "list", "--global", "--agent", "claude-code"],
    );
    let everything = run_json(&project, &registry, &["skills", "list", "--global"]);

    assert_eq!(claude["counts"]["dependency"], 1, "{claude:#}");
    assert_eq!(claude["counts"]["external"], 0, "{claude:#}");
    assert_eq!(everything["counts"]["external"], 0, "{everything:#}");
}
