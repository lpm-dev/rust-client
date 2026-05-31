mod support;

use support::{TempProject, lpm};

fn plugin_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("plugins")
}

fn seed_installed_plugin(project: &TempProject, name: &str, version: &str) {
    std::fs::create_dir_all(
        plugin_root(project)
            .join(name)
            .join(version)
            .join("darwin-arm64"),
    )
    .expect("failed to seed installed plugin directory");
}

fn plugin_entry<'a>(plugins: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    plugins
        .iter()
        .find(|plugin| plugin["name"] == serde_json::json!(name))
        .unwrap_or_else(|| panic!("missing plugin entry for {name}"))
}

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

#[test]
fn plugin_list_json_reports_installed_versions_and_known_latest_versions() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    seed_installed_plugin(&project, "oxlint", "1.57.0");

    let output = lpm(&project)
        .args(["plugin", "list", "--json"])
        .output()
        .expect("failed to run lpm plugin list --json");

    assert!(
        output.status.success(),
        "lpm plugin list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("plugin list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    let plugins = envelope["plugins"]
        .as_array()
        .expect("plugins must be an array");
    assert_eq!(envelope["count"], serde_json::json!(plugins.len()));

    let oxlint = plugin_entry(plugins, "oxlint");
    assert_eq!(oxlint["installed"], serde_json::json!(["1.57.0"]));
    assert_eq!(oxlint["latest"], serde_json::json!("1.58.0"));

    let biome = plugin_entry(plugins, "biome");
    assert_eq!(biome["installed"], serde_json::json!([]));
    assert_eq!(biome["latest"], serde_json::json!("2.4.10"));

    insta::assert_json_snapshot!("plugin_list_json_one_installed_plugin", envelope);
}

#[test]
fn plugin_list_human_renders_table_and_slim_completion() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    seed_installed_plugin(&project, "oxlint", "1.57.0");
    seed_installed_plugin(&project, "biome", "2.4.10");

    let output = lpm(&project)
        .args(["--color=always", "plugin", "list"])
        .output()
        .expect("failed to run lpm plugin list");

    assert!(
        output.status.success(),
        "lpm plugin list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi(&stdout_raw);
    assert!(
        stdout.contains("Plugin") && stdout.contains("Current") && stdout.contains("Latest"),
        "plugin list must render a table header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("oxlint") && stdout.contains("1.57.0"),
        "plugin list must render the installed plugin row, got:\n{stdout}"
    );
    assert!(
        stdout.contains("biome") && stdout.contains("current"),
        "plugin list must render the current status row, got:\n{stdout}"
    );
    assert!(
        stdout.contains("update available"),
        "plugin list must render update status, got:\n{stdout}"
    );
    assert!(
        stdout_raw.contains("\u{1b}[2mPlugin")
            && stdout_raw.contains("\u{1b}[2m1.57.0")
            && stdout_raw.contains("\u{1b}[33m1.58.0")
            && stdout_raw.contains("\u{1b}[33mupdate available")
            && stdout_raw.contains("\u{1b}[32mcurrent"),
        "plugin list must apply slim color roles, got:\n{stdout_raw:?}"
    );

    let stderr_raw = String::from_utf8_lossy(&output.stderr);
    let stderr = strip_ansi(&stderr_raw);
    assert!(
        stderr.contains("✓ 2 plugins installed"),
        "plugin list must report a slim installed count, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "plugin list status output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn plugin_update_json_reports_zero_updates_when_no_plugins_are_installed() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["plugin", "update", "--json"])
        .output()
        .expect("failed to run lpm plugin update --json");

    assert!(
        output.status.success(),
        "lpm plugin update --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("plugin update --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(0));
    assert_eq!(envelope["updated"], serde_json::json!([]));

    insta::assert_json_snapshot!("plugin_update_json_zero_installed_plugins", envelope);
}

#[test]
fn plugin_update_human_zero_installed_uses_slim_warning() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["plugin", "update"])
        .output()
        .expect("failed to run lpm plugin update");

    assert!(
        output.status.success(),
        "lpm plugin update failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No plugins installed to update"),
        "plugin update must use a slim warning when nothing is installed, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "plugin update status output must not use cliclack gutter output, got:\n{stderr}"
    );
}
