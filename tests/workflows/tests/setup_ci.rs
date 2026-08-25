//! Workflow tests for `lpm setup ci npmrc` (CI `.npmrc` generation).
//!
//! The OIDC contract paths are pinned by the cli-binary survivor
//! [`crates/lpm-cli/tests/oidc_setup_snippet_contract.rs`]. This file
//! covers the non-OIDC branches that don't need a real CI environment:
//!
//! - scoped registry config (default)
//! - removed `--proxy` flag is rejected before writing `.npmrc`
//! - legacy `proxy = true` config no longer widens `.npmrc`
//! - `--registry <url>` overrides the registry URL
//! - JSON envelope shape (path, content, uses_env_var, oidc, proxy)
//! - missing-token failure leaves the project unchanged

mod support;

use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn git(project: &TempProject, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(project.path())
        .output()
        .unwrap_or_else(|error| panic!("failed to run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── default scoped config ────────────────────────────────────────────

#[test]
fn setup_ci_without_bearer_fails_before_writing_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc");

    assert!(!output.status.success(), "missing bearer must fail");
    assert!(
        !project.file_exists(".npmrc"),
        "failure must not write .npmrc"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("LPM_TOKEN") && stderr.contains("lpm login"),
        "failure must explain how to supply a bearer, got:\n{stderr}"
    );
}

#[test]
fn setup_ci_refuses_to_write_a_tracked_npmrc() {
    let project = TempProject::empty(r#"{"name":"tracked","version":"1.0.0"}"#);
    project.write_private_file(".npmrc", "fund=false\n");
    git(&project, &["init", "-q"]);
    git(&project, &["add", "--", ".npmrc"]);

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("run setup ci npmrc with tracked npmrc");

    assert!(!output.status.success(), "tracked npmrc must be refused");
    assert_eq!(project.read_file(".npmrc"), "fund=false\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("tracked"),
        "error must explain the git-index risk: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn setup_ci_fails_closed_when_git_tracking_cannot_be_inspected() {
    let project = TempProject::empty(r#"{"name":"git-unavailable","version":"1.0.0"}"#);
    let empty_path = tempfile::tempdir().expect("create empty PATH");

    let output = lpm(&project)
        .env("PATH", empty_path.path())
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci without git on PATH");

    assert!(
        !output.status.success(),
        "setup ci must not write a bearer when Git tracking cannot be inspected"
    );
    assert!(!project.file_exists(".npmrc"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Git tracking"),
        "failure must identify the unavailable tracking check: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn setup_ci_fails_closed_when_git_dir_poisoning_breaks_repository_inspection() {
    let project = TempProject::empty(r#"{"name":"tracked","version":"1.0.0"}"#);
    project.write_private_file(".npmrc", "fund=false\n");
    git(&project, &["init", "-q"]);
    git(&project, &["add", "--", ".npmrc"]);

    let output = lpm(&project)
        .env("GIT_DIR", project.path().join("missing-git-dir"))
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with a poisoned GIT_DIR");

    assert!(
        !output.status.success(),
        "failed repository inspection must not be treated as a non-repository"
    );
    assert_eq!(project.read_file(".npmrc"), "fund=false\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("tracked"),
        "failure must identify the tracked npmrc: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn setup_ci_ignores_a_poisoned_git_index_when_checking_tracked_npmrc() {
    let project = TempProject::empty(r#"{"name":"tracked","version":"1.0.0"}"#);
    project.write_private_file(".npmrc", "fund=false\n");
    git(&project, &["init", "-q"]);
    git(&project, &["add", "--", ".npmrc"]);

    let output = lpm(&project)
        .env(
            "GIT_INDEX_FILE",
            project.path().join("missing-alternate-index"),
        )
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with a poisoned GIT_INDEX_FILE");

    assert!(
        !output.status.success(),
        "tracked npmrc must still be refused"
    );
    assert_eq!(project.read_file(".npmrc"), "fund=false\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("tracked"),
        "the real repository index must remain authoritative: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn setup_ci_refuses_a_linked_npmrc_without_reading_or_replacing_its_target() {
    let project = TempProject::empty(r#"{"name":"linked","version":"1.0.0"}"#);
    let external = tempfile::NamedTempFile::new().expect("create external npmrc target");
    std::fs::write(
        external.path(),
        "//registry.npmjs.org/:_authToken=external-secret\n",
    )
    .expect("seed external npmrc target");
    std::os::unix::fs::symlink(external.path(), project.path().join(".npmrc"))
        .expect("link project npmrc");

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with linked npmrc");

    assert!(!output.status.success(), "linked npmrc must be refused");
    assert!(
        std::fs::symlink_metadata(project.path().join(".npmrc"))
            .expect("linked npmrc must remain")
            .file_type()
            .is_symlink(),
        "setup ci must not replace the linked path"
    );
    assert_eq!(
        std::fs::read_to_string(external.path()).expect("read external target"),
        "//registry.npmjs.org/:_authToken=external-secret\n"
    );
}

#[test]
fn setup_ci_writes_literal_env_bearer_and_preserves_unrelated_config() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    std::fs::write(
        project.path().join(".npmrc"),
        "registry=https://registry.example.test/\nfund=false\n",
    )
    .expect("seed .npmrc");

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc --color=always");

    assert!(output.status.success(), "lpm setup ci npmrc failed");
    let npmrc = project.read_file(".npmrc");
    assert!(
        npmrc.contains("registry=https://registry.example.test/")
            && npmrc.contains("fund=false")
            && npmrc.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/")
            && npmrc.contains("ci-runtime-token"),
        "generated block must preserve unrelated config and contain the resolved bearer:\n{npmrc}"
    );
    assert!(
        !npmrc.contains("${LPM_TOKEN}"),
        "project .npmrc must not contain sensitive environment expansion"
    );

    let mut parsed = lpm_registry::npmrc::NpmrcConfig::parse_layer_with_options(
        &npmrc,
        "project/.npmrc",
        Some(project.path()),
        true,
        &|_| None,
    );
    parsed.finalize();
    assert!(
        parsed.security_warnings.is_empty() && parsed.errors.is_empty(),
        "generated project layer must pass the real trust parser: {:?} {:?}",
        parsed.security_warnings,
        parsed.errors
    );
    assert!(parsed.scope_registries.contains_key("@lpm.dev"));
    assert!(
        parsed
            .auth_for_url("https://lpm.example.test/api/registry/@lpm.dev/pkg")
            .is_some(),
        "generated literal bearer must resolve for the scoped registry origin"
    );
    assert!(
        parsed
            .auth_for_url("https://lpm.example.test/unrelated")
            .is_none(),
        "the generated bearer must not be sent to unrelated same-origin paths"
    );
}

#[test]
fn setup_ci_rejects_unsafe_registry_urls_before_writing_credentials() {
    for registry in [
        "https://user:password@lpm.example.test",
        "https://lpm.example.test?registry=other",
        "https://lpm.example.test#fragment",
        "ftp://lpm.example.test",
        "http://lpm.example.test",
        "https://lpm.example.test/\n//attacker.example/:_authToken=stolen",
    ] {
        let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
        let output = lpm(&project)
            .env("LPM_TOKEN", "ci-runtime-token")
            .args(["--registry", registry, "setup", "ci", "npmrc"])
            .output()
            .expect("run setup ci with an unsafe registry URL");

        assert!(
            !output.status.success(),
            "unsafe registry URL was accepted: {registry:?}"
        );
        assert!(
            !project.file_exists(".npmrc"),
            "unsafe registry URL wrote credentials: {registry:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("registry URL"),
            "failure must identify the rejected registry URL {registry:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn setup_ci_does_not_duplicate_an_existing_registry_endpoint_suffix() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args([
            "--registry",
            "https://lpm.example.test/api/registry/",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("run setup ci with a registry endpoint URL");

    assert!(
        output.status.success(),
        "setup ci failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let npmrc = project.read_file(".npmrc");
    assert!(
        npmrc.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        "the normalized endpoint must be written once:\n{npmrc}"
    );
    assert!(
        !npmrc.contains("/api/registry/api/registry"),
        "the endpoint suffix must not be duplicated:\n{npmrc}"
    );
}

#[test]
fn setup_ci_writes_the_global_explicit_bearer() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let registry_url = "https://lpm.example.test";

    let output = lpm(&project)
        .args([
            "--registry",
            registry_url,
            "--token",
            "explicit-setup-token",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("run setup ci with a global explicit token");

    assert!(
        output.status.success(),
        "setup ci ignored the global explicit token:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.read_file(".npmrc").contains("explicit-setup-token"),
        "the generated npmrc must contain the explicit bearer"
    );
}

#[test]
fn setup_ci_command_registry_override_uses_its_stored_session() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let registry_url = "https://setup-command.example.test";
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some("command-registry-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm(&project)
        .args(["setup", "ci", "npmrc", "--registry", registry_url])
        .output()
        .expect("run setup ci with a command registry override");

    assert!(
        output.status.success(),
        "setup ci did not use the command registry session:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let npmrc = project.read_file(".npmrc");
    assert!(npmrc.contains("command-registry-token"));
    assert!(npmrc.contains(registry_url));
}

#[tokio::test]
async fn setup_ci_propagates_a_stored_session_refresh_failure() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(mock.server())
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("expired-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2000-01-01T00:00:00Z"),
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci during a refresh outage");

    assert!(!output.status.success());
    assert!(!project.file_exists(".npmrc"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("HTTP 503"),
        "setup ci hid the refresh failure:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn setup_ci_replaces_unterminated_generated_block_without_dropping_following_config() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    std::fs::write(
        project.path().join(".npmrc"),
        "# LPM Registry (generated by lpm setup ci npmrc)\n\
         //lpm.example.test/:_authToken=stale-token\n\
         @lpm.dev:registry=https://lpm.example.test/api/registry/\n\
         fund=false\n",
    )
    .expect("seed unterminated generated block");

    let output = lpm(&project)
        .env("LPM_TOKEN", "replacement-token")
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("run setup ci against unterminated block");

    assert!(
        output.status.success(),
        "setup failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let npmrc = project.read_file(".npmrc");
    assert!(npmrc.contains("fund=false"));
    assert!(npmrc.contains("replacement-token"));
    assert!(!npmrc.contains("stale-token"));
}

#[tokio::test]
async fn setup_ci_self_revokes_the_displaced_setup_token_before_writing_the_new_bearer() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let previous_token = "lpm_pre_marker_read_only_token";
    let mock = MockRegistry::start().await;
    project.write_file(
        ".npmrc",
        &format!(
            "# LPM Registry (generated by lpm setup local — do not commit)\n\
             @lpm.dev:registry={}/api/registry\n\
             {}/api/registry/:_authToken={previous_token}\n\
             # End LPM Registry\n",
            mock.url(),
            mock.url().replace("http:", "")
        ),
    );
    mock.with_npmrc_token_self_revoke(previous_token, 200, 1)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "oidc-or-read-replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci over a setup-local token");

    assert!(
        output.status.success(),
        "the displaced token must retire with its own bearer, independently of replacement auth:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let npmrc = project.read_file(".npmrc");
    assert!(npmrc.contains("oidc-or-read-replacement-token"));
    assert!(!npmrc.contains(previous_token));
}

#[tokio::test]
async fn setup_ci_refuses_a_generated_predecessor_bearer_for_another_registry_scope() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         @lpm.dev:registry={}/api/registry\n\
         //attacker.invalid/api/registry/:_authToken=foreign-predecessor\n\
         # End LPM Registry\n",
        mock.url(),
    );
    project.write_file(".npmrc", &original);

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with a foreign generated bearer scope");

    assert!(!output.status.success());
    assert_eq!(project.read_file(".npmrc"), original);
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "a predecessor bearer must never be sent to a different registry origin"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("scope"),
        "failure must identify the generated scope mismatch: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn setup_ci_write_failure_happens_before_displaced_token_revocation() {
    use std::os::unix::fs::PermissionsExt as _;

    let project = TempProject::empty(r#"{"name":"unwritable","version":"1.0.0"}"#);
    let previous_token = "lpm_active_setup_token";
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         @lpm.dev:registry={}/api/registry\n\
         {}/api/registry/:_authToken={previous_token}\n\
         # End LPM Registry\n",
        mock.url(),
        mock.url().replace("http:", "")
    );
    project.write_file(".npmrc", &original);
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/revoke-project"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mock.server())
        .await;

    let original_mode = std::fs::metadata(project.path())
        .expect("project metadata")
        .permissions()
        .mode();
    std::fs::set_permissions(project.path(), std::fs::Permissions::from_mode(0o500))
        .expect("make project unwritable");
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci in unwritable project");
    std::fs::set_permissions(
        project.path(),
        std::fs::Permissions::from_mode(original_mode),
    )
    .expect("restore project permissions");

    assert!(!output.status.success(), "the npmrc write must fail");
    assert_eq!(project.read_file(".npmrc"), original);
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "a recoverable local write failure must happen before remote token revocation"
    );
}

#[tokio::test]
async fn setup_ci_refuses_to_self_revoke_and_rewrite_the_same_setup_local_bearer() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let previous_token = "lpm_same_setup_local_bearer";
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         @lpm.dev:registry={}/api/registry\n\
         {}/api/registry/:_authToken={previous_token}\n\
         # End LPM Registry\n",
        mock.url(),
        mock.url().replace("http:", "")
    );
    project.write_file(".npmrc", &original);

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", previous_token)
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with the displaced token as replacement auth");

    assert!(
        !output.status.success(),
        "setup ci must not revoke and rewrite the same bearer"
    );
    assert_eq!(project.read_file(".npmrc"), original);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("different bearer"),
        "the failure must explain how to supply a usable replacement credential"
    );
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "the same bearer must be rejected before self-revocation"
    );
}

#[tokio::test]
async fn setup_ci_treats_an_inactive_displaced_bearer_as_completed_self_revocation() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let previous_token = "lpm_already_revoked_setup_token";
    let mock = MockRegistry::start().await;
    project.write_file(
        ".npmrc",
        &format!(
            "# LPM Registry (generated by lpm setup local — do not commit)\n\
             @lpm.dev:registry={}/api/registry\n\
             {}/api/registry/:_authToken={previous_token}\n\
             # End LPM Registry\n",
            mock.url(),
            mock.url().replace("http:", "")
        ),
    );
    mock.with_npmrc_token_self_revoke(previous_token, 401, 1)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("retry setup ci after the displaced token became inactive");

    assert!(
        output.status.success(),
        "an inactive predecessor proves there is nothing left to retire:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let npmrc = project.read_file(".npmrc");
    assert!(npmrc.contains("replacement-token"));
    assert!(!npmrc.contains(previous_token));
}

#[tokio::test]
async fn setup_ci_forbidden_self_revocation_leaves_the_displaced_bearer_unchanged() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let previous_token = "lpm_non_revocable_setup_token";
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         @lpm.dev:registry={}/api/registry\n\
         {}/api/registry/:_authToken={previous_token}\n\
         # End LPM Registry\n",
        mock.url(),
        mock.url().replace("http:", "")
    );
    project.write_file(".npmrc", &original);
    mock.with_npmrc_token_self_revoke(previous_token, 403, 1)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci when the Registry denies self-revocation");

    assert!(!output.status.success());
    assert_eq!(project.read_file(".npmrc"), original);
    assert!(
        !project.read_file(".npmrc").contains("replacement-token"),
        "the replacement bearer must not be written after denied retirement"
    );
}

#[tokio::test]
async fn setup_ci_redacts_a_displaced_bearer_echoed_by_self_revocation() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let previous_token = "lpm_secret_displaced_project_bearer";
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         @lpm.dev:registry={}/api/registry\n\
         {}/api/registry/:_authToken={previous_token}\n\
         # End LPM Registry\n",
        mock.url(),
        mock.url().replace("http:", "")
    );
    project.write_file(".npmrc", &original);
    mock.with_npmrc_token_self_revoke_error(
        previous_token,
        403,
        &format!("invalid {previous_token}\u{1b}[31m"),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["--json", "setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci when self-revocation echoes the displaced bearer");

    assert!(!output.status.success());
    assert_eq!(project.read_file(".npmrc"), original);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains(previous_token),
        "the displaced bearer must never reach JSON or terminal output:\n{combined}"
    );
    assert!(
        combined.contains("<redacted>"),
        "the bounded Registry error should retain a safe redaction marker:\n{combined}"
    );
    assert!(
        !combined.contains('\u{1b}'),
        "Registry-controlled terminal characters must be removed:\n{combined}"
    );
}

#[tokio::test]
async fn setup_ci_does_not_honor_repository_retirement_markers_outside_a_generated_block() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let attacker_selected_id = "11111111-1111-4111-8111-111111111111";
    let mock = MockRegistry::start().await;
    project.write_file(
        ".npmrc",
        &format!(
            "registry=https://registry.example.test/\n\
             # LPM pending project token retirement id: {attacker_selected_id}\n"
        ),
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with an untrusted retirement marker");

    assert!(
        output.status.success(),
        "an arbitrary repository comment must not authorize token revocation:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "setup ci must not send a revocation selected by repository-controlled marker text"
    );
    assert!(
        project.read_file(".npmrc").contains(attacker_selected_id),
        "unrelated repository config must be preserved"
    );
}

#[tokio::test]
async fn setup_ci_preserves_pending_setup_local_recovery_for_setup_local_to_finish() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         # LPM pending project token id: 22222222-2222-4222-8222-222222222222\n\
         # LPM previous project token hash: {}\n\
         @lpm.dev:registry={}/api/registry\n\
         {}/api/registry/:_authToken=lpm_{}\n\
         # End LPM Registry\n",
        "a".repeat(64),
        mock.url(),
        mock.url().replace("http:", ""),
        "b".repeat(64),
    );
    project.write_file(".npmrc", &original);

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "replacement-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci while setup local recovery is pending");

    assert!(!output.status.success());
    assert_eq!(project.read_file(".npmrc"), original);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("lpm setup local"),
        "the failure must direct the user to the command that owns the pending replacement"
    );
    assert!(mock.server().received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn setup_ci_ambiguous_self_revocation_leaves_the_old_bearer_for_a_safe_retry() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let previous_token = "lpm_pre_marker_read_only_token";
    let mock = MockRegistry::start().await;
    let original = format!(
        "# LPM Registry (generated by lpm setup local — do not commit)\n\
         @lpm.dev:registry={}/api/registry\n\
         {}/api/registry/:_authToken={previous_token}\n\
         # End LPM Registry\n",
        mock.url(),
        mock.url().replace("http:", "")
    );
    project.write_file(".npmrc", &original);
    mock.with_npmrc_token_self_revoke_ambiguous_then_success(previous_token)
        .await;

    let first = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with an ambiguous retirement response");
    assert!(!first.status.success());
    let pending = project.read_file(".npmrc");
    assert!(
        pending.contains("ci-runtime-token"),
        "a usable replacement must be staged before ambiguous revocation"
    );
    assert!(
        pending.contains(previous_token),
        "the protected recovery state must retain the predecessor for retry"
    );

    let second = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "different-runtime-token")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("retry setup ci retirement");
    assert!(
        second.status.success(),
        "retry must confirm cleanup:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let final_npmrc = project.read_file(".npmrc");
    assert!(final_npmrc.contains("ci-runtime-token"));
    assert!(!final_npmrc.contains("different-runtime-token"));
    assert!(!final_npmrc.contains(previous_token));

    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let first_body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let second_body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(first_body, serde_json::json!({ "self": true }));
    assert_eq!(first_body, second_body);
}

#[test]
fn setup_ci_stray_end_marker_does_not_extend_an_unterminated_generated_block() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    std::fs::write(
        project.path().join(".npmrc"),
        "# End LPM Registry\n\
         # LPM Registry (generated by lpm setup ci npmrc)\n\
         //lpm.example.test/:_authToken=stale-token\n\
         @lpm.dev:registry=https://lpm.example.test/api/registry/\n\
         fund=false\n",
    )
    .expect("seed generated block with a stray earlier end marker");

    let output = lpm(&project)
        .env("LPM_TOKEN", "lpm_replacement-token")
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("run setup ci against unterminated block");

    assert!(
        output.status.success(),
        "setup failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let npmrc = project.read_file(".npmrc");
    assert!(
        npmrc.contains("fund=false"),
        "an earlier stray end marker must not cause unrelated trailing config to be dropped:\n{npmrc}"
    );
    assert!(npmrc.contains("lpm_replacement-token"));
    assert!(!npmrc.contains("stale-token"));
}

#[test]
fn setup_ci_rejects_malformed_bearer_before_writing_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-token\u{1b}injected")
        .args(["setup", "ci", "npmrc"])
        .output()
        .expect("run setup ci with malformed bearer");

    assert!(!output.status.success());
    assert!(!project.file_exists(".npmrc"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("malformed"),
        "failure should identify the malformed bearer"
    );
}

#[test]
fn setup_ci_explicit_oidc_failure_does_not_fall_back_to_stored_token() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let registry_url = "https://lpm.example.test";
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some("stored-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .args(["--registry", registry_url, "setup", "ci", "npmrc", "--oidc"])
        .output()
        .expect("run setup ci with unavailable explicit OIDC");

    assert!(!output.status.success());
    assert!(!project.file_exists(".npmrc"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no fallback was used"),
        "explicit OIDC failure should explain that stored credentials were not used"
    );
}

#[test]
fn setup_ci_proxy_flag_is_rejected_before_dot_npmrc_is_written() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
            "--proxy",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc --proxy");

    assert!(
        !output.status.success(),
        "lpm setup ci npmrc --proxy must be rejected"
    );
    assert!(
        !project.file_exists(".npmrc"),
        "rejected --proxy setup must not write .npmrc"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--proxy"),
        "rejection must name the removed flag, got:\n{stderr}"
    );
}

#[test]
fn setup_ci_ignores_legacy_proxy_config_when_writing_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("create isolated lpm home");
    std::fs::write(lpm_dir.join("config.toml"), "proxy = true\n")
        .expect("write legacy proxy config");

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc");

    assert!(
        output.status.success(),
        "lpm setup ci npmrc failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let npmrc =
        std::fs::read_to_string(project.path().join(".npmrc")).expect("setup ci must write .npmrc");
    assert!(
        npmrc.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        "legacy proxy config must not widen setup output, got:\n{npmrc}",
    );
    assert!(
        !npmrc.lines().any(|line| line.starts_with("registry=")),
        "legacy proxy config must not write a bare registry line, got:\n{npmrc}",
    );
}

// ─── --json envelope ──────────────────────────────────────────────────

#[test]
fn setup_ci_json_envelope_carries_path_content_and_flag_state() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args([
            "--registry",
            "https://lpm.example.test",
            "--json",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc --json");

    assert!(output.status.success(), "lpm setup ci npmrc --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("setup ci --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["proxy"], serde_json::json!(false));
    assert_eq!(envelope["oidc"], serde_json::json!(false));
    assert_eq!(envelope["uses_env_var"], serde_json::json!(true));
    assert_eq!(envelope["storage_backend"], serde_json::Value::Null);
    assert_eq!(envelope["storage_degraded"], serde_json::json!(false));

    let path = envelope["path"].as_str().expect("path must be a string");
    assert!(
        path.ends_with(".npmrc"),
        "envelope path must point at .npmrc, got: {path}"
    );

    let content = envelope["content"]
        .as_str()
        .expect("content must be a string");
    assert!(
        content.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        "envelope content must include the scoped registry line, got:\n{content}",
    );
}

#[test]
fn setup_ci_scoped_flag_is_an_unknown_argument_without_writes() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["setup", "ci", "npmrc", "--scoped"])
        .output()
        .expect("run setup ci with removed flag");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--scoped"));
    assert!(!project.file_exists(".npmrc"));
}

#[test]
fn setup_ci_json_reports_file_backed_storage_backend_for_stored_token() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let registry_url = "https://lpm.example.test";
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some("stored-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm(&project)
        .args(["--registry", registry_url, "--json", "setup", "ci", "npmrc"])
        .output()
        .expect("failed to run lpm setup ci npmrc --json");

    assert!(
        output.status.success(),
        "lpm setup ci npmrc --json with stored token failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("setup ci --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["uses_env_var"], serde_json::json!(false));
    assert_eq!(
        envelope["storage_backend"],
        serde_json::json!("encrypted_file_fallback")
    );
    assert_eq!(envelope["storage_degraded"], serde_json::json!(true));
}

#[test]
fn setup_ci_npmrc_rejects_explicit_env_without_writing_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_TOKEN", "ci-runtime-token")
        .args(["--json", "setup", "ci", "npmrc", "--env", "production"])
        .output()
        .expect("failed to run lpm setup ci npmrc with --env");

    assert!(
        !output.status.success(),
        "setup ci npmrc must reject explicit --env"
    );
    assert!(
        !project.file_exists(".npmrc"),
        "rejected --env must not write .npmrc"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!("setup ci npmrc error must be JSON: {error}\n---\n{stdout}")
    });
    assert_eq!(envelope["error_code"], serde_json::json!("script"));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("--env") && error.contains("npmrc")),
        "error must identify the irrelevant flag and target: {envelope}"
    );
    insta::assert_json_snapshot!("setup_ci_npmrc_rejects_env_json", envelope);
}
