mod support;

use support::{TempProject, lpm};

#[test]
fn hosts_clean_json_removes_lpm_managed_blocks_with_yes() {
    let project = TempProject::empty(r#"{"name":"hosts-test","version":"1.0.0"}"#);
    let hosts_path = project.path().join("hosts");
    let original = "127.0.0.1 localhost\n\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n\n10.0.0.1 router\n# >>> lpm:project-def >>>\n127.0.0.1 web.test\n# <<< lpm:project-def <<<\n";
    std::fs::write(&hosts_path, original).expect("write hosts fixture");

    let output = lpm(&project)
        .args(["--json", "hosts", "clean", "--yes"])
        .env("LPM_HOSTS_FILE", &hosts_path)
        .output()
        .expect("run lpm hosts clean");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("hosts clean --json must be valid JSON: {err}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["cleaned"], serde_json::json!(true));
    assert_eq!(envelope["removedBlocks"], serde_json::json!(2));

    insta::with_settings!({ filters => vec![
        (r#""hostsFile":\s*"[^"]+""#, r#""hostsFile": "[HOSTS_FILE]""#),
        (r#""backupPath":\s*"[^"]+""#, r#""backupPath": "[BACKUP_PATH]""#),
    ]}, {
        insta::assert_json_snapshot!("hosts_clean_json_removes_lpm_managed_blocks", envelope);
    });

    let content = std::fs::read_to_string(&hosts_path).expect("read cleaned hosts file");
    assert_eq!(content, "127.0.0.1 localhost\n\n10.0.0.1 router\n");
    let backup_path = project.home().join(".lpm").join("hosts.bak");
    let backup = std::fs::read_to_string(&backup_path).expect("read hosts backup");
    assert_eq!(backup, original);
}

#[test]
fn hosts_clean_aborts_non_interactive_without_yes_before_mutation() {
    let project = TempProject::empty(r#"{"name":"hosts-test","version":"1.0.0"}"#);
    let hosts_path = project.path().join("hosts");
    let original = "127.0.0.1 localhost\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n";
    std::fs::write(&hosts_path, original).expect("write hosts fixture");

    let output = lpm(&project)
        .args(["hosts", "clean"])
        .env("LPM_HOSTS_FILE", &hosts_path)
        .output()
        .expect("run lpm hosts clean");

    assert!(
        !output.status.success(),
        "hosts clean should fail without non-interactive consent"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-interactive shell: pass `--yes` to consent")
            && stderr.contains("to removing 1")
            && stderr.contains("LPM-managed hosts file block"),
        "stderr should explain the consent requirement, got:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&hosts_path).expect("read hosts file"),
        original
    );
    assert!(!project.home().join(".lpm").join("hosts.bak").exists());
}
