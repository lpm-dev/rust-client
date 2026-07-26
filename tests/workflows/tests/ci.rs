mod support;

use support::{TempProject, lpm};

const HOSTILE_ENV_NAME: &str =
    "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";

fn assert_hostile_env_name_is_inline_safe(context: &str, rendered: &str) {
    assert!(
        rendered.matches("safe?FORGED?rewritten?end").count() >= 2,
        "{context} must preserve the readable env name in both generated commands, got:\n{rendered}"
    );
    for attacker_fragment in [
        "\nFORGED", "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}", "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "{context} retained attacker fragment {attacker_fragment:?}:\n{rendered}"
        );
    }
}

#[test]
fn ci_env_github_actions_masks_secret_values_and_emits_github_env_commands() {
    let project = TempProject::empty(r#"{"name":"ci-test","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
  "envSchema": {
    "vars": {
      "API_KEY": { "required": true, "secret": true },
      "PUBLIC_URL": { "required": true }
    }
  }
}"#,
    );
    project.write_file(
        ".env",
        "PUBLIC_URL=https://example.test\nAPI_KEY=supersecret\n",
    );

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "1")
        .args(["env", "print", "--ci"])
        .output()
        .expect("failed to run lpm env print --ci");

    assert!(
        output.status.success(),
        "lpm env print --ci failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        concat!(
            "::add-mask::supersecret\n",
            "echo 'API_KEY=supersecret' >> \"$GITHUB_ENV\"\n",
            "echo 'PUBLIC_URL=https://example.test' >> \"$GITHUB_ENV\"",
        ),
        "GitHub Actions output must mask secrets before writing deterministic env commands"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Emitted 2 environment variables for GitHub Actions"),
        "env print --ci must report a slim terminus on stderr, got:\n{stderr}"
    );
}

#[test]
fn ci_env_shell_output_reports_generic_ci_terminus_on_stderr() {
    let project = TempProject::empty(r#"{"name":"ci-test","version":"1.0.0"}"#);
    project.write_file(
        ".env",
        "PUBLIC_URL=https://example.test\nAPI_KEY=local-key\n",
    );

    let output = lpm(&project)
        .env_remove("GITHUB_ACTIONS")
        .env_remove("VERCEL")
        .args(["env", "print", "--ci"])
        .output()
        .expect("failed to run lpm env print --ci");

    assert!(
        output.status.success(),
        "lpm env print --ci failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("export API_KEY=local-key")
            && stdout.contains("export PUBLIC_URL=https://example.test"),
        "shell output must stay machine-consumable on stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Emitted 2 environment variables for generic CI"),
        "env print --ci shell path must report the generic CI terminus, got:\n{stderr}"
    );
}

#[test]
fn ci_env_output_writes_dotenv_file_for_selected_env_mode() {
    let project = TempProject::empty(r#"{"name":"ci-test","version":"1.0.0"}"#);
    project.write_file(".env", "SHARED=base\n");
    project.write_file(
        ".env.production",
        "API_URL=https://prod.example.test\nGREETING=hello world\n",
    );

    let output = lpm(&project)
        .args(["env", "export", "--ci", "--env=production", "ci.env"])
        .output()
        .expect("failed to run lpm env export --ci");

    assert!(
        output.status.success(),
        "lpm env export --ci failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert_eq!(
        project.read_file("ci.env"),
        concat!(
            "API_URL=https://prod.example.test\n",
            "GREETING=\"hello world\"\n",
            "SHARED=base"
        )
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Wrote 3 vars to ci.env"),
        "env export --ci must report the file write, got:\n{stderr}"
    );
}

#[test]
fn ci_setup_github_actions_uses_project_vault_id_and_requested_env_name() {
    let project = TempProject::empty(r#"{"name":"ci-test","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{ "vault": "vault-123" }"#);

    let output = lpm(&project)
        .args(["setup", "ci", "github-actions", "--env=preview"])
        .output()
        .expect("failed to run lpm setup ci github-actions");

    assert!(
        output.status.success(),
        "lpm setup ci github-actions failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("GitHub Actions OIDC Setup"),
        "setup output must identify the GitHub Actions snippet, got:\n{stdout}"
    );
    assert!(
        stdout.contains("lpm env pull --oidc --env=preview --output=.env"),
        "setup output must thread the requested env name through the pull step, got:\n{stdout}"
    );
    assert!(
        stdout.contains("LPM_VAULT_ID: vault-123"),
        "setup output must use the project vault id when present, got:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "lpm env oidc allow --provider=github --repo=<owner/repo> \
             --workflow=.github/workflows/deploy.yml --branch=main --env=preview"
        ),
        "setup output must authorize the same workflow path displayed above it, got:\n{stdout}"
    );
}

#[test]
fn ci_setup_github_actions_env_name_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"ci-controls","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "setup",
            "ci",
            "github-actions",
            &format!("--env={HOSTILE_ENV_NAME}"),
        ])
        .output()
        .expect("failed to run GitHub Actions setup with terminal controls");

    assert!(output.status.success(), "GitHub Actions setup must succeed");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hostile_env_name_is_inline_safe("GitHub Actions setup output", &rendered);
}

// ─── setup ci gitlab ──────────────────────────────────────────────────

#[test]
fn ci_setup_gitlab_emits_id_tokens_block_and_authorization_command() {
    let project = TempProject::empty(r#"{"name":"ci-gitlab","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["setup", "ci", "gitlab"])
        .output()
        .expect("failed to run lpm setup ci gitlab");

    assert!(
        output.status.success(),
        "lpm setup ci gitlab failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("GitLab CI OIDC Setup"),
        "setup output must identify the GitLab CI snippet, got:\n{stdout}"
    );
    assert!(
        stdout.contains("LPM_OIDC_TOKEN") && stdout.contains("aud: https://lpm.dev"),
        "setup snippet must declare the `LPM_OIDC_TOKEN` id_tokens block, got:\n{stdout}"
    );
    assert!(
        stdout.contains("lpm env oidc allow --provider=gitlab")
            && stdout.contains("--project-id=<numeric-project-id>")
            && !stdout.contains("--repo=<project-path>")
            && !stdout.contains("--workflow="),
        "setup output must print the matching authorization command, got:\n{stdout}"
    );
}

#[test]
fn ci_setup_gitlab_with_env_flag_threads_the_env_name() {
    let project = TempProject::empty(r#"{"name":"ci-gitlab","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["setup", "ci", "gitlab", "--env=staging"])
        .output()
        .expect("failed to run lpm setup ci gitlab --env=staging");

    assert!(output.status.success(), "setup ci gitlab --env failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--env=staging"),
        "setup output must thread the requested env name into the pull step + authorization command, got:\n{stdout}"
    );
}

#[test]
fn ci_setup_gitlab_env_name_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"ci-controls","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "setup",
            "ci",
            "gitlab",
            &format!("--env={HOSTILE_ENV_NAME}"),
        ])
        .output()
        .expect("failed to run GitLab setup with terminal controls");

    assert!(output.status.success(), "GitLab setup must succeed");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hostile_env_name_is_inline_safe("GitLab setup output", &rendered);
}

#[test]
fn ci_setup_unknown_platform_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"ci","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["setup", "ci", "bitbucket"])
        .output()
        .expect("failed to run lpm setup ci bitbucket");

    assert!(
        !output.status.success(),
        "unknown CI platform must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("github-actions") && stderr.contains("gitlab"),
        "stderr must list valid platforms, got:\n{stderr}",
    );
}

/// `lpm --json setup ci <unknown-platform>` surfaces the same
/// validation error as a structured envelope. Pins the JSON contract
/// shared by `setup ci github-actions` and `setup ci gitlab` (the
/// happy paths emit shell-format on stdout, not envelopes — see the
/// existing tests above — but the dispatcher's unknown-platform
/// rejection is the cheapest envelope contract for both surfaces).
#[test]
fn ci_setup_unknown_platform_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"ci","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "setup", "ci", "bitbucket"])
        .output()
        .expect("failed to run lpm --json setup ci bitbucket");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json setup ci unknown error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("github-actions") && s.contains("gitlab")),
        "error must list valid platforms, got: {envelope}",
    );
}

#[test]
fn ci_setup_without_platform_arg_fails_with_usage_message() {
    let project = TempProject::empty(r#"{"name":"ci","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["setup", "ci"])
        .output()
        .expect("failed to run lpm setup ci (no platform)");

    assert!(
        !output.status.success(),
        "setup ci without platform must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage:") || stderr.contains("Available"),
        "stderr must show usage, got:\n{stderr}",
    );
}

#[test]
fn ci_without_lockfile_fails_as_frozen_install() {
    let project = TempProject::empty(r#"{"name":"ci-frozen","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "ci",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .output()
        .expect("failed to run lpm ci");

    assert!(
        !output.status.success(),
        "lpm ci must fail when the frozen lockfile is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Frozen lockfile") && stderr.contains("lpm.lock"),
        "stderr must explain that lpm ci is a frozen install requiring lpm.lock, got:\n{stderr}"
    );
}
