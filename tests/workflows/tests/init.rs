mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn blank_project_dir() -> TempProject {
    let project = TempProject::empty(r#"{"name":"placeholder","version":"1.0.0"}"#);
    std::fs::remove_file(project.path().join("package.json"))
        .expect("failed to remove placeholder package.json");
    project
}

#[tokio::test]
async fn init_yes_human_output_uses_slim_success() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;
    mock.with_whoami("neo", "neo@example.com").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color=always", "init", "-y"])
        .output()
        .expect("failed to run lpm init -y");

    assert!(
        output.status.success(),
        "lpm init -y failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = strip_ansi(&raw);
    assert!(
        combined.contains("✓ Wrote package.json"),
        "init should use a slim success line, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Wrote AGENTS.md"),
        "init should report the AGENTS.md package-manager hint, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Added lpm.lockb binary to .gitattributes"),
        "init should report the binary lockfile git attribute, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Done · initialized @lpm.dev/neo.package"),
        "init should show the initialized package name, got:\n{combined}"
    );
    assert!(
        raw.contains("\u{1b}[36m@lpm.dev/neo.package\u{1b}[39m"),
        "init should color the full package name as an identifier, got:\n{raw:?}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "init output should not use bordered/cliclack glyphs, got:\n{combined}"
    );
}

#[tokio::test]
async fn init_yes_json_uses_profile_username_and_creates_gitattributes() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;
    mock.with_whoami("neo", "neo@example.com").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["init", "-y", "--json"])
        .output()
        .expect("failed to run lpm init --json");

    assert!(
        output.status.success(),
        "lpm init --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("init --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["target"], serde_json::json!("lpm"));
    assert_eq!(envelope["name"], serde_json::json!("@lpm.dev/neo.package"));
    assert_eq!(envelope["version"], serde_json::json!("1.0.0"));
    assert_eq!(envelope["agents_status"], serde_json::json!("created"));
    assert_eq!(envelope["lpm_json_status"], serde_json::json!("skipped"));
    assert_eq!(envelope["gitattributes_ready"], serde_json::json!(true));

    insta::with_settings!({
        filters => vec![
            (r#""/[^"]+/package\.json""#, r#""[PACKAGE_JSON]""#),
            (r#""/[^"]+/AGENTS\.md""#, r#""[AGENTS_MD]""#),
            (r#""lpm@[0-9]+\.[0-9]+\.[0-9]+""#, r#""lpm@[VERSION]""#),
        ],
    }, {
        insta::assert_json_snapshot!("init_json_envelope_default_owner", envelope);
    });

    let package_json: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("created package.json must be valid JSON");
    assert_eq!(
        package_json["name"],
        serde_json::json!("@lpm.dev/neo.package")
    );
    assert_eq!(
        package_json["packageManager"]
            .as_str()
            .map(|value| value.starts_with("lpm@")),
        Some(true),
        "packageManager should pin lpm"
    );
    assert!(
        project
            .read_file("AGENTS.md")
            .contains("This project uses lpm."),
        "init must write the AGENTS.md lpm hint"
    );
    assert!(
        !project.file_exists("CLAUDE.md"),
        "init must not create provider-specific agent files"
    );
    assert!(
        project.file_exists(".gitattributes"),
        "init must pre-create .gitattributes"
    );
    let gitattributes = project.read_file(".gitattributes");
    assert!(
        gitattributes.contains("lpm.lockb binary"),
        ".gitattributes must mark lpm.lockb as binary, got:\n{gitattributes}"
    );
}

#[tokio::test]
async fn init_yes_falls_back_to_literal_username_when_whoami_unavailable() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["init", "-y", "--json"])
        .output()
        .expect("failed to run lpm init --json");

    assert!(
        output.status.success(),
        "lpm init --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let package_json: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("created package.json must be valid JSON");
    assert_eq!(
        package_json["name"],
        serde_json::json!("@lpm.dev/username.package"),
        "missing whoami response must fall back to the literal username owner"
    );
}

#[tokio::test]
async fn init_npm_yes_writes_npm_name_publish_config_and_agents_hint() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;
    mock.with_whoami_expected("neo", "neo@example.com", 0).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["init", "--npm", "-y", "--name", "@acme/widget", "--json"])
        .output()
        .expect("failed to run lpm init --npm --json");

    assert!(
        output.status.success(),
        "lpm init --npm --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("init --npm --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["target"], serde_json::json!("npm"));
    assert_eq!(envelope["name"], serde_json::json!("@acme/widget"));
    assert_eq!(envelope["lpm_json_status"], serde_json::json!("created"));
    assert_eq!(envelope["agents_status"], serde_json::json!("created"));

    let package_json: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("created package.json must be valid JSON");
    assert_eq!(package_json["name"], serde_json::json!("@acme/widget"));
    assert_eq!(
        package_json["packageManager"]
            .as_str()
            .map(|value| value.starts_with("lpm@")),
        Some(true),
        "packageManager should pin lpm"
    );

    let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
        .expect("created lpm.json must be valid JSON");
    assert_eq!(
        lpm_json["publish"]["registries"],
        serde_json::json!(["npm"]),
        "npm-target init must make plain `lpm publish` target npm"
    );

    let agents = project.read_file("AGENTS.md");
    assert!(
        agents.contains("Install dependencies with `lpm install`."),
        "AGENTS.md must teach agents to use lpm, got:\n{agents}"
    );
    assert!(
        agents.contains("Use `--json` when you need machine-readable output from lpm commands."),
        "AGENTS.md must teach agents to prefer JSON when parsing lpm output, got:\n{agents}"
    );
    assert!(
        !agents.contains("Keep `lpm.lock`"),
        "AGENTS.md must not imply agents manually sync lockfiles, got:\n{agents}"
    );
}

#[tokio::test]
async fn init_lpm_yes_honors_owner_and_package_name_flags() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "init",
            "--lpm",
            "-y",
            "--owner",
            "acme",
            "--name",
            "design-system",
            "--json",
        ])
        .output()
        .expect("failed to run lpm init --lpm --json");

    assert!(
        output.status.success(),
        "lpm init --lpm --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let package_json: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("created package.json must be valid JSON");
    assert_eq!(
        package_json["name"],
        serde_json::json!("@lpm.dev/acme.design-system")
    );
    assert!(
        !project.file_exists("lpm.json"),
        "lpm-target init should not need publish config"
    );
}

#[tokio::test]
async fn init_npm_no_agents_leaves_agents_file_absent() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "init",
            "--npm",
            "-y",
            "--name",
            "plain-package",
            "--no-agents",
        ])
        .output()
        .expect("failed to run lpm init --npm --no-agents");

    assert!(
        output.status.success(),
        "lpm init --npm --no-agents failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !project.file_exists("AGENTS.md"),
        "--no-agents must not write AGENTS.md"
    );
}

#[tokio::test]
async fn init_appends_agents_hint_without_removing_existing_agent_guidance() {
    let project = blank_project_dir();
    let mock = MockRegistry::start().await;
    project.write_file("AGENTS.md", "# Local Rules\n\n- Keep this sentence.\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["init", "--npm", "-y", "--name", "widget"])
        .output()
        .expect("failed to run lpm init with existing AGENTS.md");

    assert!(
        output.status.success(),
        "lpm init failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let agents = project.read_file("AGENTS.md");
    assert!(
        agents.contains("- Keep this sentence."),
        "existing AGENTS.md content must be preserved, got:\n{agents}"
    );
    assert!(
        agents.contains("This project uses lpm."),
        "AGENTS.md must receive the lpm managed block, got:\n{agents}"
    );
    assert_eq!(
        agents.matches("This project uses lpm.").count(),
        1,
        "AGENTS.md must not duplicate the lpm block"
    );
}
