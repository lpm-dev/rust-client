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
        .args(["init", "-y"])
        .output()
        .expect("failed to run lpm init -y");

    assert!(
        output.status.success(),
        "lpm init -y failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        combined.contains("✓ Created package.json"),
        "init should use a slim success line, got:\n{combined}"
    );
    assert!(
        combined.contains("@lpm.dev/neo.package"),
        "init should show the created package name, got:\n{combined}"
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
    assert_eq!(envelope["name"], serde_json::json!("@lpm.dev/neo.package"));
    assert_eq!(envelope["version"], serde_json::json!("1.0.0"));

    insta::with_settings!({
        filters => vec![
            (r#""/[^"]+/package\.json""#, r#""[PACKAGE_JSON]""#),
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
