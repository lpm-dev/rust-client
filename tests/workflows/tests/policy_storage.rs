//! Workflow coverage for release-age and lifecycle trust storage boundaries.

mod support;

use lpm_common::atomic_write::is_atomic_temp_name;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm, lpm_with_registry, write_signed_unlock_for};

const VERSION: &str = "1.0.0";
const PROJECT_EXCLUDED: &str = "project-excluded";
const USER_EXCLUDED: &str = "@company/user-excluded";
const CLI_EXCLUDED: &str = "cli-excluded";

fn config_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm/config.toml")
}

fn global_trust_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm/global/trusted-dependencies.json")
}

fn seed_global_lifecycle_trust(project: &TempProject) {
    let path = global_trust_path(project);
    std::fs::create_dir_all(path.parent().expect("global trust path has a parent")).unwrap();
    std::fs::write(
        path,
        r#"{
  "schema_version": 1,
  "trusted": {
    "global-sentinel@1.0.0": {
      "integrity": "sha512-global-sentinel",
      "scriptHash": "sha256-global-sentinel"
    }
  }
}
"#,
    )
    .unwrap();
}

fn assert_success(output: &std::process::Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn json_output(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "command output must be JSON: {error}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn assert_no_atomic_temp_files(directory: &std::path::Path) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if let Some(name) = name.to_str() {
            assert!(
                !is_atomic_temp_name(name),
                "atomic write left a temporary file at {}",
                entry.path().display()
            );
        }
    }
}

async fn mount_recent_packages(mock: &MockRegistry, names: &[&str]) {
    let published_at = (chrono::Utc::now() - chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut batch = Vec::with_capacity(names.len());

    for name in names {
        let tarball = make_tarball(name, VERSION);
        mock.with_package_published_at(name, VERSION, &tarball, &published_at)
            .await;
        batch.push(serde_json::json!({
            "name": name,
            "dist-tags": { "latest": VERSION },
            "versions": {
                VERSION: {
                    "name": name,
                    "version": VERSION,
                    "dist": {
                        "tarball": mock.tarball_url(name, VERSION),
                        "integrity": compute_integrity(&tarball),
                    },
                    "dependencies": {}
                }
            },
            "time": { VERSION: published_at }
        }));
    }

    mock.with_batch_metadata(batch).await;
}

#[tokio::test]
async fn release_age_layers_merge_for_install_without_cross_persistence() {
    let project = TempProject::empty(
        r#"{
  "name": "policy-storage",
  "version": "1.0.0",
  "dependencies": {
    "project-excluded": "1.0.0",
    "@company/user-excluded": "1.0.0",
    "cli-excluded": "1.0.0"
  },
  "lpm": {
    "minimumReleaseAge": 86400
  }
}"#,
    );
    project.write_file("lpm.lock", "lockfile-before-policy-commands\n");
    seed_global_lifecycle_trust(&project);
    let global_trust_before = std::fs::read(global_trust_path(&project)).unwrap();

    let user_add = lpm(&project)
        .args([
            "--json",
            "config",
            "release-age-exclude",
            "add",
            "@company/*",
        ])
        .output()
        .expect("run user release-age exclusion add");
    assert_success(&user_add, "user exclusion add");

    let exact_project_selector = format!("{PROJECT_EXCLUDED}@{VERSION}");
    let project_add = lpm(&project)
        .args([
            "--json",
            "trust",
            "release-age-exclude",
            "add",
            &exact_project_selector,
        ])
        .output()
        .expect("run project release-age exclusion add");
    assert_success(&project_add, "project exclusion add");

    let project_list = lpm(&project)
        .args(["--json", "trust", "release-age-exclude", "list"])
        .output()
        .expect("list project release-age exclusions");
    assert_success(&project_list, "project exclusion list");
    assert_eq!(
        json_output(&project_list)["exclusions"],
        serde_json::json!([exact_project_selector])
    );

    let user_list = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "list"])
        .output()
        .expect("list user release-age exclusions");
    assert_success(&user_list, "user exclusion list");
    assert_eq!(
        json_output(&user_list)["exclusions"],
        serde_json::json!(["@company/*"])
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        manifest["lpm"]["minimumReleaseAgeExclude"],
        serde_json::json!([format!("{PROJECT_EXCLUDED}@{VERSION}")])
    );
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(config_path(&project)).unwrap()).unwrap();
    assert_eq!(
        config["minimum-release-age-exclude"],
        toml::Value::Array(vec![toml::Value::String("@company/*".to_string())])
    );
    assert_eq!(
        std::fs::read(global_trust_path(&project)).unwrap(),
        global_trust_before
    );

    let mock = MockRegistry::start().await;
    mount_recent_packages(&mock, &[PROJECT_EXCLUDED, USER_EXCLUDED, CLI_EXCLUDED]).await;
    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--min-release-age-exclude",
            CLI_EXCLUDED,
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install with merged release-age exclusions");
    assert_success(&install, "install with merged release-age exclusions");

    let lockfile_path = project.path().join("lpm.lock");
    let lockfile_after_install = std::fs::read(&lockfile_path).unwrap();
    let lockfile_text = String::from_utf8_lossy(&lockfile_after_install);
    for policy_key in [
        "minimumReleaseAgeExclude",
        "minimum-release-age-exclude",
        "trustedDependencies",
        "trustedScopes",
    ] {
        assert!(
            !lockfile_text.contains(policy_key),
            "lpm.lock must not persist policy key {policy_key}"
        );
    }

    let project_remove = lpm(&project)
        .args([
            "trust",
            "release-age-exclude",
            "remove",
            &format!("{PROJECT_EXCLUDED}@{VERSION}"),
        ])
        .output()
        .expect("remove project release-age exclusion");
    assert_success(&project_remove, "project exclusion remove");
    assert_eq!(
        std::fs::read(&lockfile_path).unwrap(),
        lockfile_after_install
    );

    let user_remove = lpm(&project)
        .args(["config", "release-age-exclude", "remove", "@company/*"])
        .output()
        .expect("remove user release-age exclusion");
    assert_success(&user_remove, "user exclusion remove");
    assert_eq!(
        std::fs::read(&lockfile_path).unwrap(),
        lockfile_after_install
    );
    assert_eq!(
        std::fs::read(global_trust_path(&project)).unwrap(),
        global_trust_before
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(manifest["lpm"].get("minimumReleaseAgeExclude").is_none());
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(config_path(&project)).unwrap()).unwrap();
    assert!(config.get("minimum-release-age-exclude").is_none());
    assert_no_atomic_temp_files(project.path());
    assert_no_atomic_temp_files(config_path(&project).parent().unwrap());
}

#[test]
fn workspace_project_policy_commands_write_only_the_current_member_manifest() {
    let project = TempProject::empty(
        r#"{
  "name": "policy-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "lpm": {
    "minimumReleaseAgeExclude": ["root-only"]
  }
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"workspace-app","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{"name":"workspace-sibling","version":"1.0.0"}"#,
    );
    project.write_file("lpm.lock", "workspace-lockfile-sentinel\n");
    let config = config_path(&project);
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "minimum-release-age-exclude = [\"user-only\"]\n").unwrap();
    seed_global_lifecycle_trust(&project);

    let root_before = std::fs::read(project.path().join("package.json")).unwrap();
    let sibling_before =
        std::fs::read(project.path().join("packages/sibling/package.json")).unwrap();
    let lockfile_before = std::fs::read(project.path().join("lpm.lock")).unwrap();
    let config_before = std::fs::read(&config).unwrap();
    let global_trust_before = std::fs::read(global_trust_path(&project)).unwrap();
    let member_dir = project.path().join("packages/app");
    write_signed_unlock_for(&project, &member_dir, &["trust-scope-widen"]);

    let mut release_add = lpm(&project);
    let release_add = release_add
        .current_dir(&member_dir)
        .args([
            "--json",
            "trust",
            "release-age-exclude",
            "add",
            "member-policy@1.0.0",
        ])
        .output()
        .expect("add member release-age exclusion");
    assert_success(&release_add, "member release-age exclusion add");

    let mut scope_add = lpm(&project);
    let scope_add = scope_add
        .current_dir(&member_dir)
        .args(["--json", "trust", "lifecycle-scope", "add", "@company/*"])
        .output()
        .expect("add member lifecycle scope");
    assert_success(&scope_add, "member lifecycle scope add");

    let mut release_list = lpm(&project);
    let release_list = release_list
        .current_dir(&member_dir)
        .args(["--json", "trust", "release-age-exclude", "list"])
        .output()
        .expect("list member release-age exclusions");
    assert_success(&release_list, "member release-age exclusion list");
    assert_eq!(
        json_output(&release_list)["exclusions"],
        serde_json::json!(["member-policy@1.0.0"])
    );

    let mut scope_list = lpm(&project);
    let scope_list = scope_list
        .current_dir(&member_dir)
        .args(["--json", "trust", "lifecycle-scope", "list"])
        .output()
        .expect("list member lifecycle scopes");
    assert_success(&scope_list, "member lifecycle scope list");
    assert_eq!(
        json_output(&scope_list)["scopes"],
        serde_json::json!(["@company/*"])
    );

    let member: serde_json::Value =
        serde_json::from_str(&project.read_file("packages/app/package.json")).unwrap();
    assert_eq!(
        member["lpm"]["minimumReleaseAgeExclude"],
        serde_json::json!(["member-policy@1.0.0"])
    );
    assert_eq!(
        member["lpm"]["scripts"]["trustedScopes"],
        serde_json::json!(["@company/*"])
    );

    assert_eq!(
        std::fs::read(project.path().join("package.json")).unwrap(),
        root_before
    );
    assert_eq!(
        std::fs::read(project.path().join("packages/sibling/package.json")).unwrap(),
        sibling_before
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lock")).unwrap(),
        lockfile_before
    );
    assert_eq!(std::fs::read(&config).unwrap(), config_before);
    assert_eq!(
        std::fs::read(global_trust_path(&project)).unwrap(),
        global_trust_before
    );
    assert!(!member_dir.join("lpm.lock").exists());
    assert_no_atomic_temp_files(&member_dir);
}
