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

/// `Command` starts no `npm` by that name on Windows, where it is a
/// script, so the fixture that publishes with it runs on Unix only.
#[cfg(unix)]
#[test]
fn the_registry_fixture_s_npm_reads_no_configuration_below_a_node_prefix() {
    let home = tempfile::tempdir().unwrap();
    let node_prefix = tempfile::tempdir().unwrap();
    std::fs::create_dir(node_prefix.path().join("etc")).unwrap();
    std::fs::write(
        node_prefix.path().join("etc").join("npmrc"),
        "tag=from-the-machine\n",
    )
    .unwrap();
    let user_config = home.path().join(".npmrc");
    // Nothing but the file below the prefix may decide the setting: not a
    // project's configuration above the working directory, nor what the
    // process that runs the tests has in its environment.
    let tag_read_by = |mut npm: std::process::Command| {
        let output = npm
            .current_dir(home.path())
            .env_remove("npm_config_tag")
            .env_remove("NPM_CONFIG_TAG")
            .env_remove("npm_config_prefix")
            .env("NPM_CONFIG_PREFIX", node_prefix.path())
            .args(["config", "get", "tag"])
            .output()
            .expect("run npm");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    let mut reads_the_machine_s = std::process::Command::new("npm");
    reads_the_machine_s
        .env_remove("npm_config_userconfig")
        .env_remove("npm_config_globalconfig")
        .env_remove("NPM_CONFIG_GLOBALCONFIG")
        .env("NPM_CONFIG_USERCONFIG", &user_config);
    assert_eq!(
        tag_read_by(reads_the_machine_s),
        "from-the-machine",
        "an npm that names no global configuration reads the one below its prefix"
    );

    let fixture_s = support::verdaccio::npm_configured_by(&user_config, home.path());

    assert_eq!(tag_read_by(fixture_s), "latest");
}

/// The harness gives every command its own home, npm configuration and
/// registry. A command a test builds for itself gets the account's. So a
/// test file neither looks the binary up itself nor starts a command at
/// the path the harness gives it.
#[test]
fn no_workflow_test_builds_the_lpm_command_itself() {
    fn sources(directory: &Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let harness = tests.join("support").join("mod.rs");
    let this_file = tests.join("support_helpers.rs");
    let mut found = Vec::new();
    sources(&tests, &mut found);
    assert!(found.contains(&harness), "{}", harness.display());
    assert!(found.contains(&this_file), "{}", this_file.display());
    let lookups = [
        concat!("cargo_bin(", "\"lpm-rs\")"),
        concat!("cargo_bin!(", "\"lpm-rs\")"),
        concat!("CARGO_BIN_EXE_", "lpm-rs"),
    ];

    let mut offenders = Vec::new();
    for path in found
        .iter()
        .filter(|path| **path != harness && **path != this_file)
    {
        let source = std::fs::read_to_string(path).unwrap();
        for (index, line) in source.lines().enumerate() {
            let looks_it_up = lookups.iter().any(|lookup| line.contains(lookup));
            let starts_it = line.contains("Command::new(") && line.contains("lpm_binary");
            if looks_it_up || starts_it {
                offenders.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "find the binary with `support::lpm_binary` and build its command with `support::lpm` \
         or `support::lpm_from_path`: {offenders:?}"
    );
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
