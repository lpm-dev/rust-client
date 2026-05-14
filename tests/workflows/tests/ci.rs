mod support;

use support::{TempProject, lpm};

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
        .args(["ci", "env"])
        .output()
        .expect("failed to run lpm ci env");

    assert!(
        output.status.success(),
        "lpm ci env failed:\nstdout: {}\nstderr: {}",
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
        .args(["ci", "env", "--env=production", "--output=ci.env"])
        .output()
        .expect("failed to run lpm ci env --output");

    assert!(
        output.status.success(),
        "lpm ci env --output failed:\nstdout: {}\nstderr: {}",
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
        stderr.contains("wrote 3 vars to ci.env"),
        "ci env --output must report the file write, got:\n{stderr}"
    );
}

#[test]
fn ci_setup_github_actions_uses_project_vault_id_and_requested_env_name() {
    let project = TempProject::empty(r#"{"name":"ci-test","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{ "vault": "vault-123" }"#);

    let output = lpm(&project)
        .args(["ci", "setup", "github-actions", "--env=preview"])
        .output()
        .expect("failed to run lpm ci setup github-actions");

    assert!(
        output.status.success(),
        "lpm ci setup github-actions failed:\nstdout: {}\nstderr: {}",
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
            "lpm env oidc allow --provider=github --repo=<owner/repo> --branch=main --env=preview"
        ),
        "setup output must print the matching authorization command, got:\n{stdout}"
    );
}

// ─── ci setup gitlab ──────────────────────────────────────────────────

#[test]
fn ci_setup_gitlab_emits_id_tokens_block_and_authorization_command() {
    let project = TempProject::empty(r#"{"name":"ci-gitlab","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["ci", "setup", "gitlab"])
        .output()
        .expect("failed to run lpm ci setup gitlab");

    assert!(
        output.status.success(),
        "lpm ci setup gitlab failed:\nstdout: {}\nstderr: {}",
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
        stdout.contains("lpm env oidc allow --provider=gitlab"),
        "setup output must print the matching authorization command, got:\n{stdout}"
    );
}

#[test]
fn ci_setup_gitlab_with_env_flag_threads_the_env_name() {
    let project = TempProject::empty(r#"{"name":"ci-gitlab","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["ci", "setup", "gitlab", "--env=staging"])
        .output()
        .expect("failed to run lpm ci setup gitlab --env=staging");

    assert!(output.status.success(), "ci setup gitlab --env failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--env=staging"),
        "setup output must thread the requested env name into the pull step + authorization command, got:\n{stdout}"
    );
}

#[test]
fn ci_setup_unknown_platform_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"ci","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["ci", "setup", "bitbucket"])
        .output()
        .expect("failed to run lpm ci setup bitbucket");

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

/// `lpm --json ci setup <unknown-platform>` surfaces the same
/// validation error as a structured envelope. Pins the JSON contract
/// shared by `ci setup github-actions` and `ci setup gitlab` (the
/// happy paths emit shell-format on stdout, not envelopes — see the
/// existing tests above — but the dispatcher's unknown-platform
/// rejection is the cheapest envelope contract for both surfaces).
#[test]
fn ci_setup_unknown_platform_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"ci","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "ci", "setup", "bitbucket"])
        .output()
        .expect("failed to run lpm --json ci setup bitbucket");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json ci setup unknown error path must emit JSON: {e}\n---\n{stdout}")
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
        .args(["ci", "setup"])
        .output()
        .expect("failed to run lpm ci setup (no platform)");

    assert!(
        !output.status.success(),
        "ci setup without platform must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage:") || stderr.contains("Available"),
        "stderr must show usage, got:\n{stderr}",
    );
}
