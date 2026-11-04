mod support;

use std::path::Path;

use support::verdaccio::verdaccio_log_confirms_current_instance;

#[test]
fn verdaccio_startup_log_rejects_stale_process_with_same_port() {
    let logs = "config file - /tmp/old/config.yaml\nhttp address - http://127.0.0.1:4873/";

    assert!(!verdaccio_log_confirms_current_instance(
        logs,
        Path::new("/tmp/current/config.yaml"),
        "http://127.0.0.1:4873",
    ));
}

#[test]
fn verdaccio_startup_log_rejects_current_config_on_wrong_port() {
    let logs = "config file - /tmp/current/config.yaml\nhttp address - http://127.0.0.1:4874/";

    assert!(!verdaccio_log_confirms_current_instance(
        logs,
        Path::new("/tmp/current/config.yaml"),
        "http://127.0.0.1:4873",
    ));
}

#[test]
fn verdaccio_startup_log_accepts_current_config_and_listen_url() {
    let logs = concat!(
        "config file - \u{1b}[32m/tmp/current/config.yaml\u{1b}[37m\n",
        "http address - \u{1b}[32mhttp://127.0.0.1:4873/\u{1b}[37m\n",
    );

    assert!(verdaccio_log_confirms_current_instance(
        logs,
        Path::new("/tmp/current/config.yaml"),
        "http://127.0.0.1:4873",
    ));
}

#[cfg(unix)]
#[test]
fn commands_launch_the_lpm_under_test_once_and_a_staged_binary_only_when_warmed() {
    const LAUNCH_LOGS: &str = "LPM_WARM_UP_TEST_LAUNCH_LOGS";
    let Some(logs) = std::env::var_os(LAUNCH_LOGS) else {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::TempDir::new().unwrap();
        for name in ["lpm-rs", "staged-lpm"] {
            let binary = directory.path().join(name);
            std::fs::write(
                &binary,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}.launches'\n",
                    binary.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands_launch_the_lpm_under_test_once_and_a_staged_binary_only_when_warmed",
                "--nocapture",
            ])
            .env("CARGO_BIN_EXE_lpm-rs", directory.path().join("lpm-rs"))
            .env(LAUNCH_LOGS, directory.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };

    let logs = Path::new(&logs);
    let launches = |name: &str| {
        std::fs::read_to_string(logs.join(format!("{name}.launches"))).unwrap_or_default()
    };
    let project = support::TempProject::empty("{}");

    drop(support::lpm(&project));
    assert_eq!(launches("lpm-rs"), "--version\n");
    drop(support::lpm_spawnable(&project));
    drop(support::lpm(&project));
    assert_eq!(launches("lpm-rs"), "--version\n");

    let staged = logs.join("staged-lpm");
    drop(support::lpm_from_path(&project, &staged));
    drop(support::lpm_spawnable_from_path(&project, &staged));
    assert_eq!(launches("staged-lpm"), "");
    support::warm_binary(&staged);
    support::warm_binary(&staged);
    assert_eq!(launches("staged-lpm"), "--version\n");
}
