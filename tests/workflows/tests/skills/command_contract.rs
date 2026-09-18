use super::*;
use support::auth_state::{SessionSeed, read_credentials, seed_sessions};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

fn managed_project(agents: &[&str]) -> TempProject {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_standard_skill(
        &project,
        "team-skills",
        "release-notes",
        "Summarize commits into release notes.",
    );
    let mut command = lpm(&project);
    command.args([
        "skills",
        "add",
        "./team-skills",
        "--skill",
        "release-notes",
        "--project",
        "--yes",
    ]);
    for agent in agents {
        command.args(["--agent", agent]);
    }
    command.assert().success();
    project
}

fn make_claude_only(project: &TempProject) {
    project.write_file("team-skills/release-notes/SKILL.md", "---\nname: release-notes\ndescription: A useful release-notes skill for workflow testing\ncontext: fork\n---\nSummarize commits into release notes.\n");
}

#[test]
fn readding_checks_compatibility_of_retained_targets_before_writes() {
    let project = managed_project(&["codex"]);
    let before = project.read_file(".agents/skills/release-notes/SKILL.md");
    let state = project.read_file(".lpm/managed-skills/skills.lock.json");
    make_claude_only(&project);
    lpm(&project)
        .args([
            "skills",
            "add",
            "./team-skills",
            "--skill",
            "release-notes",
            "--agent",
            "claude-code",
            "--project",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not compatible with codex"));
    assert_eq!(
        project.read_file(".agents/skills/release-notes/SKILL.md"),
        before
    );
    assert_eq!(
        project.read_file(".lpm/managed-skills/skills.lock.json"),
        state
    );
    assert!(!project.path().join(".claude/skills/release-notes").exists());
}

#[test]
fn enabling_checks_compatibility_after_disabled_target_content_updates() {
    let project = managed_project(&["codex", "claude-code"]);
    lpm(&project)
        .args([
            "skills",
            "disable",
            "release-notes",
            "--agent",
            "codex",
            "--yes",
        ])
        .assert()
        .success();
    make_claude_only(&project);
    lpm(&project)
        .args(["skills", "update", "release-notes", "--yes"])
        .assert()
        .success();
    let state = project.read_file(".lpm/managed-skills/skills.lock.json");
    lpm(&project)
        .args([
            "skills",
            "enable",
            "release-notes",
            "--agent",
            "codex",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not compatible with codex"));
    assert_eq!(
        project.read_file(".lpm/managed-skills/skills.lock.json"),
        state
    );
    assert!(!project.path().join(".agents/skills/release-notes").exists());
}

#[test]
fn clean_dry_run_leaves_a_fresh_project_unchanged() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    lpm(&project)
        .args(["skills", "clean", "--dry-run", "--json"])
        .assert()
        .success();
    assert!(
        !project.path().join(".lpm").exists(),
        "dry-run created project state"
    );
}

#[test]
fn remove_preview_deduplicates_agent_filters_and_retains_shared_content() {
    let project = managed_project(&["codex", "claude-code"]);
    let output = lpm(&project)
        .args([
            "skills",
            "remove",
            "release-notes",
            "--agent",
            "codex",
            "--agent",
            "codex",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let changes = json["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{json}");
    assert_eq!(changes[0]["action"], "remove managed target");
    lpm(&project)
        .args([
            "skills",
            "remove",
            "release-notes",
            "--agent",
            "codex",
            "--agent",
            "codex",
            "--yes",
        ])
        .assert()
        .success();
    assert!(project.file_exists(".claude/skills/release-notes/SKILL.md"));
}

#[test]
fn managed_view_rejects_oversized_canonical_files() {
    let project = managed_project(&["codex"]);
    project.write_file(
        ".agents/skills/release-notes/oversized.txt",
        &"x".repeat(2 * 1024 * 1024),
    );
    lpm(&project)
        .args(["skills", "view", "release-notes", "--json"])
        .assert()
        .failure();
}

#[tokio::test]
async fn package_skills_recovers_a_stored_session_after_concealed_denial() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("valid-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(header("authorization", "Bearer expired-access"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(header("authorization", "Bearer rotated-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"name":"owner.widget", "available":false,"skills":[]}),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
    mock.with_refresh_expected(
        "valid-refresh",
        "rotated-access",
        "rotated-refresh",
        "2099-01-01T00:00:00Z",
        1,
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["skills", "add", "@lpm.dev/owner.widget", "--list", "--json"])
        .output()
        .unwrap();
    let requests = mock.server().received_requests().await.unwrap();
    assert!(output.status.success(), "{output:?}; requests={requests:?}");
    assert_eq!(
        read_credentials(project.home())[mock.url()],
        "rotated-access"
    );
}

#[tokio::test]
async fn public_package_skills_do_not_require_session_refresh() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("expired-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0)
        .mount(mock.server())
        .await;
    lpm_with_registry(&project, &mock.url())
        .args(["skills", "add", "@lpm.dev/owner.widget", "--list", "--json"])
        .assert()
        .success();
}

#[test]
fn enabling_copied_targets_deduplicates_repeated_agent_flags() {
    let project = managed_project(&["codex", "claude-code"]);
    lpm(&project)
        .args([
            "skills",
            "add",
            "./team-skills",
            "--skill",
            "release-notes",
            "--agent",
            "codex",
            "--project",
            "--copy",
            "--yes",
        ])
        .assert()
        .success();
    lpm(&project)
        .args([
            "skills",
            "disable",
            "release-notes",
            "--agent",
            "codex",
            "--yes",
        ])
        .assert()
        .success();
    lpm(&project)
        .args([
            "skills",
            "enable",
            "release-notes",
            "--agent",
            "codex",
            "--agent",
            "codex",
            "--yes",
        ])
        .assert()
        .success();
    assert!(project.file_exists(".agents/skills/release-notes/SKILL.md"));
    assert!(project.file_exists(".claude/skills/release-notes/SKILL.md"));
}

#[test]
fn materialized_skill_with_many_directories_remains_readable() {
    let project = TempProject::empty(r#"{"name":"skills","version":"1.0.0"}"#);
    seed_standard_skill(
        &project,
        "team-skills",
        "nested-guide",
        "Use the auxiliary guidance.",
    );
    for index in 0..250 {
        project.write_file(
            &format!("team-skills/nested-guide/section-{index}/guide.txt"),
            "Read this guidance.",
        );
    }
    lpm(&project)
        .args([
            "skills",
            "add",
            "./team-skills",
            "--agent",
            "codex",
            "--project",
            "--yes",
        ])
        .assert()
        .success();
    lpm(&project)
        .args(["skills", "view", "nested-guide", "--json"])
        .assert()
        .success();
    lpm(&project)
        .args(["skills", "update", "nested-guide", "--yes"])
        .assert()
        .success();
}
