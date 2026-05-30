mod support;

use support::{TempProject, lpm};

fn config_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("config.toml")
}

fn seed_config(project: &TempProject, content: &str) {
    let path = config_path(project);
    std::fs::create_dir_all(path.parent().expect("config path must have a parent"))
        .expect("failed to create config dir");
    std::fs::write(path, content).expect("failed to seed config.toml");
}

#[test]
fn config_set_writes_value_into_isolated_home() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "config",
            "set",
            "registry",
            "https://registry.example.test",
        ])
        .output()
        .expect("failed to run lpm config set");

    assert!(
        output.status.success(),
        "lpm config set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config set --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));

    let content = std::fs::read_to_string(config_path(&project))
        .expect("config set must create ~/.lpm/config.toml in the isolated HOME");
    assert!(
        content.contains("registry = \"https://registry.example.test\""),
        "config set must persist the key, got:\n{content}"
    );
}

#[test]
fn config_set_human_uses_slim_success() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "set", "registry", "https://registry.example.test"])
        .output()
        .expect("failed to run lpm config set");

    assert!(
        output.status.success(),
        "lpm config set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Set registry = https://registry.example.test"),
        "config set must use a slim success line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config set must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn config_get_json_returns_existing_value() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(&project, "registry = \"https://registry.example.test\"\n");

    let output = lpm(&project)
        .args(["config", "get", "registry", "--json"])
        .output()
        .expect("failed to run lpm config get --json");

    assert!(
        output.status.success(),
        "lpm config get --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("config get --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["registry"],
        serde_json::json!("https://registry.example.test")
    );

    insta::assert_json_snapshot!("config_get_json_envelope_single_key", envelope);
}

#[test]
fn config_delete_removes_existing_key_and_preserves_other_entries() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ncolor = \"always\"\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "delete", "registry"])
        .output()
        .expect("failed to run lpm config delete");

    assert!(
        output.status.success(),
        "lpm config delete failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config delete --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));

    let content =
        std::fs::read_to_string(config_path(&project)).expect("config file must still exist");
    assert!(
        !content.contains("registry"),
        "config delete must remove the target key, got:\n{content}"
    );
    assert!(
        content.contains("color = \"always\""),
        "config delete must preserve unrelated entries, got:\n{content}"
    );
}

#[test]
fn config_list_json_reports_all_keys() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ncolor = \"always\"\n",
    );

    let output = lpm(&project)
        .args(["config", "list", "--json"])
        .output()
        .expect("failed to run lpm config list --json");

    assert!(
        output.status.success(),
        "lpm config list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("config list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["registry"],
        serde_json::json!("https://registry.example.test")
    );
    assert_eq!(envelope["color"], serde_json::json!("always"));

    insta::assert_json_snapshot!("config_list_json_envelope_two_keys", envelope);
}

#[test]
fn config_list_human_keeps_values_on_stdout() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ncolor = \"always\"\n",
    );

    let output = lpm(&project)
        .args(["config", "list"])
        .output()
        .expect("failed to run lpm config list");

    assert!(
        output.status.success(),
        "lpm config list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("registry") && stdout.contains("https://registry.example.test"),
        "config list must render config rows to stdout, got:\n{stdout}",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config list must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn config_get_missing_key_uses_slim_warning() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "get", "registry"])
        .output()
        .expect("failed to run lpm config get");

    assert!(
        output.status.success(),
        "lpm config get missing key failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! registry is not set"),
        "missing config key must use a slim warning, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config get must not use cliclack gutter output, got:\n{stderr}",
    );
}
