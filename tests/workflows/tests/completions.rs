mod support;

use support::{TempProject, lpm};

#[test]
fn completions_zsh_stdout_uses_lpm_bin_name_and_lists_live_commands() {
    let project = TempProject::empty(r#"{"name":"completions-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["completions", "zsh"])
        .output()
        .expect("failed to run lpm completions zsh");

    assert!(
        output.status.success(),
        "lpm completions zsh failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.stderr.is_empty(),
        "completions is a pipeable script surface and must not print human progress, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("#compdef lpm"),
        "zsh completions must target the user-facing `lpm` bin name, got:\n{stdout}"
    );
    assert!(
        stdout.contains("setup") && stdout.contains("local") && stdout.contains("ci"),
        "completion script must include the renamed setup subcommands, got:\n{stdout}"
    );
    assert!(
        stdout.contains("token-rotate"),
        "completion script must stay in sync with clap subcommands, got:\n{stdout}"
    );
}

#[test]
fn completions_bash_emits_bash_completion_script() {
    let project = TempProject::empty(r#"{"name":"completions","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["completions", "bash"])
        .output()
        .expect("failed to run lpm completions bash");

    assert!(
        output.status.success(),
        "lpm completions bash failed:\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Bash completion scripts use the `complete -F` directive and a
    // shell function named `_lpm`.
    assert!(
        stdout.contains("complete -F"),
        "bash completion must declare a completion function, got:\n{stdout}"
    );
    assert!(
        stdout.contains("_lpm"),
        "bash completion script must define _lpm shell function, got:\n{stdout}"
    );
}

#[test]
fn completions_invalid_shell_is_rejected_by_clap() {
    let project = TempProject::empty(r#"{"name":"completions","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["completions", "not-a-shell"])
        .output()
        .expect("failed to run lpm completions bogus");

    assert!(
        !output.status.success(),
        "unknown shell value must be rejected"
    );
}

#[test]
fn completions_hide_internal_commands_and_options_in_every_shell() {
    let project = TempProject::empty(r#"{"name":"public-completions"}"#);
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = lpm(&project).args(["completions", shell]).output().unwrap();
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let script = String::from_utf8_lossy(&output.stdout);
        for hidden in [
            "internal-update-check",
            "internal-hosts-file",
            "internal-security-policy",
            "internal-ts-transform",
            "__run-file",
            "self-update-probe-executable",
            "forwarder-config",
        ] {
            assert!(!script.contains(hidden), "{shell} exposed {hidden}");
        }
        for visible in ["install", "completions", "token-rotate", "setup"] {
            assert!(script.contains(visible), "{shell} omitted {visible}");
        }
    }
}

#[test]
fn completions_ignore_registry_policy_and_keep_raw_scripts_under_json() {
    let project = TempProject::empty(r#"{"name":"offline-completions"}"#);
    project.write_file("lpm.json", "not JSON");
    let normal = lpm(&project).args(["completions", "zsh"]).output().unwrap();
    let output = lpm(&project)
        .env("LPM_PROVENANCE_ENFORCE", "warm")
        .args(["completions", "zsh", "--json", "--verbose"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, normal.stdout);
    assert!(output.stderr.is_empty());
}

#[test]
fn completions_exit_cleanly_when_the_pipe_reader_closes() {
    let project = TempProject::empty(r#"{"name":"closed-completion-pipe"}"#);
    let mut child = support::lpm_spawnable(&project)
        .args(["completions", "bash"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
}
