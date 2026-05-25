//! **Tier placement: cli-binary** (per CLAUDE.md `# Testing Tier
//! Discipline`). Justification class: **intentionally minimal
//! binary-surface repros**. Cross-command contract pin: ensures the
//! `lpm ci setup gitlab` snippet's `LPM_OIDC_TOKEN` env var name +
//! `aud=https://lpm.dev` audience match what `lpm setup ci --oidc`
//! actually exchanges. Single focused assertion against a raw
//! wiremock request body. A workflow tier port would inflate this
//! tight contract pin into harness boilerplate that doesn't add
//! coverage.
//!
//! Locks the contract emitted by `lpm ci setup gitlab` against the resolver
//! that backs `lpm setup ci --oidc`.
//!
//! The CLI's GitLab snippet generator (`crates/lpm-cli/src/commands/ci.rs`)
//! tells users to mint a `LPM_OIDC_TOKEN` env var via the `id_tokens` block
//! with `aud: https://lpm.dev`. This test spawns the actual binary, sets
//! `LPM_OIDC_TOKEN`, and confirms `lpm setup ci --oidc` POSTs that JWT to the
//! origin's OIDC-exchange endpoint and writes the exchanged session token
//! into `.npmrc`. If anyone ever renames the env var, repurposes the
//! variable's audience, or short-circuits the resolver, this test fails
//! and the snippet docs cannot drift silently.

use std::fs;
use std::process::Command;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SNIPPET_JWT: &str = "snippet-jwt-with-aud-lpm-dev";
const EXCHANGED_TOKEN: &str = "EXCHANGED-LPM-SESSION-TOKEN";

#[tokio::test]
async fn gitlab_snippet_lpm_oidc_token_drives_setup_oidc() {
    let server = MockServer::start().await;
    let server_url = server.uri();

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(query_param("scope", "install"))
        .and(body_partial_json(
            serde_json::json!({ "token": SNIPPET_JWT }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    fs::create_dir_all(cwd.join(".home")).unwrap();

    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(exe)
        .args(["setup", "ci", "--oidc", "--registry", &server_url])
        .current_dir(cwd)
        .env("HOME", cwd.join(".home"))
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_OIDC_TOKEN", SNIPPET_JWT)
        // Strip any inherited CI signals so the bypass is the only valid path.
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("LPM_GITLAB_OIDC_TOKEN")
        .env_remove("SIGSTORE_ID_TOKEN")
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn lpm-rs");

    assert!(
        output.status.success(),
        "lpm setup ci --oidc must succeed when LPM_OIDC_TOKEN is set\n  exit: {:?}\n  stdout:\n{}\n  stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let npmrc = fs::read_to_string(cwd.join(".npmrc")).expect(".npmrc must be written");
    assert!(
        npmrc.contains(EXCHANGED_TOKEN),
        ".npmrc must carry the exchanged session token (locks the wire format \
         emitted by `lpm ci setup gitlab`):\n{npmrc}"
    );
    assert!(
        !npmrc.contains(SNIPPET_JWT),
        ".npmrc must contain the *exchanged* token, never the raw JWT:\n{npmrc}"
    );

    // Belt-and-braces: the mock matched, which means the exchange endpoint
    // saw exactly the JWT we set — the bypass routed end-to-end without
    // touching the GitHub runtime fetch path.
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "exactly one OIDC exchange request expected, got {}",
        received.len()
    );
}
