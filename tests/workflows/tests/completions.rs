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
        stdout.contains("#compdef lpm"),
        "zsh completions must target the user-facing `lpm` bin name, got:\n{stdout}"
    );
    assert!(
        stdout.contains("setup-npmrc"),
        "completion script must include shipped subcommands, got:\n{stdout}"
    );
    assert!(
        stdout.contains("token-rotate"),
        "completion script must stay in sync with clap subcommands, got:\n{stdout}"
    );
}
