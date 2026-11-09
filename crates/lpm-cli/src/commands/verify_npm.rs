//! `lpm verify-npm`: prove that this LPM.dev account owns an npm account.
//!
//! LPM.dev holds the usernames of popular npm users for them. The proof is a
//! package published under the npm user's own scope, which only that npm
//! account can publish to: `@<npm user>/lpm-verify`, carrying a token the
//! Registry issued to this account. The Registry reads it from npm, links
//! the npm account, and gives the account the username it waits for when
//! that npm account can claim it. The package is then unpublished. The npm
//! token never leaves this machine.

use crate::commands::npm_auth;
use crate::commands::publish_common::compute_hashes;
use crate::commands::publish_npm::{self, NPM_REGISTRY_URL};
use crate::commands::web_auth;
use crate::{install_ui, output};
use lpm_common::LpmError;
use lpm_registry::{NpmVerificationResult, NpmVerificationToken, RegistryClient};
use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

const NPM_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const NPM_RESPONSE_MAX_BYTES: usize = 1024 * 1024;
/// npm serves a new package within seconds, but its CDN can lag.
const PROOF_WAIT: Duration = Duration::from_secs(90);
/// The Registry allows 12 checks a minute per account.
const PROOF_CHECK_INTERVAL: Duration = Duration::from_secs(6);
/// Registry codes that mean npm hasn't served the package yet.
const NOT_YET_CODES: [&str; 3] = ["PACKAGE_NOT_FOUND", "TOKEN_NOT_FOUND", "NPM_UNAVAILABLE"];

pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    let npm_token = npm_auth::resolve_token_auth()?;
    let http = npm_http_client()?;

    let npm_username = npm_whoami(&http, NPM_REGISTRY_URL, npm_token.token()).await?;
    if !json_output {
        install_ui::done_untrusted(&format!("Signed in to npm as {npm_username}"));
    }

    let issued = client.npm_verification_token().await?;
    if !json_output {
        explain_waiting_name(&issued, &npm_username);
    }

    let package_name = format!("@{npm_username}/{}", issued.package_name);
    let version = proof_version();
    let manifest = proof_manifest(&package_name, &version, &issued);
    let tarball = proof_tarball(&manifest)?;
    let hashes = compute_hashes(&tarball);

    if !json_output {
        install_ui::phase_untrusted(&format!("Publishing {package_name}@{version} to npm"));
    }
    let published = publish_npm::publish_to_npm(
        npm_token.token(),
        &package_name,
        &version,
        &manifest,
        &Arc::new(tarball),
        &hashes,
        None,
        "public",
        "latest",
        NPM_REGISTRY_URL,
        false,
        json_output,
        false,
    )
    .await?;
    if !published.success {
        let reason = published.error.unwrap_or_else(|| "npm refused it".into());
        return Err(LpmError::Registry(format!(
            "could not publish {package_name} to npm: {reason}. npm refuses to publish a package again for 24 hours after it was unpublished; if that's the reason, try again tomorrow."
        )));
    }

    if !json_output {
        install_ui::phase("Waiting for LPM.dev to find it on npm");
    }
    let proof = wait_for_proof(client, &npm_username, PROOF_WAIT, PROOF_CHECK_INTERVAL).await;

    if !json_output {
        install_ui::phase_untrusted(&format!("Removing {package_name} from npm"));
    }
    let unpublished = unpublish_npm_package(
        &http,
        NPM_REGISTRY_URL,
        &package_name,
        npm_token.token(),
        json_output,
    )
    .await;

    let proof = proof?;
    report(
        &proof,
        &package_name,
        unpublished.as_ref().err(),
        json_output,
    );
    Ok(())
}

fn npm_http_client() -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(NPM_REQUEST_TIMEOUT)
        .user_agent(format!("lpm-rs/{}", crate::build_version::version()))
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to create HTTP client: {e}")))
}

/// Tells the person which username they wait for, and warns when the npm
/// account they're signed in to can't claim it.
fn explain_waiting_name(issued: &NpmVerificationToken, npm_username: &str) {
    let Some(pending) = issued.pending_username.as_deref() else {
        return;
    };
    let claimants = &issued.pending_username_npm_accounts;
    if claimants.is_empty() || claimants.iter().any(|name| name == npm_username) {
        install_ui::detail_untrusted(&format!(
            "You're waiting for the username {pending}; this proof gives it to you."
        ));
        return;
    }
    install_ui::warn_untrusted(&format!(
        "{pending} is held for the npm user {}, but you're signed in to npm as {npm_username}. This proves {npm_username} and leaves {pending} waiting.",
        claimants.join(" or ")
    ));
}

/// npm never takes a version number twice, even after an unpublish, so
/// each proof gets its own.
fn proof_version() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    format!("1.0.{seconds}")
}

fn proof_manifest(
    package_name: &str,
    version: &str,
    issued: &NpmVerificationToken,
) -> serde_json::Value {
    let mut manifest = serde_json::json!({
        "name": package_name,
        "version": version,
        "description": "Proves this npm account to LPM.dev. Safe to remove.",
    });
    manifest[issued.field.as_str()] = serde_json::Value::String(issued.token.clone());
    manifest
}

/// A package holding only its `package.json`, as npm expects it.
fn proof_tarball(manifest: &serde_json::Value) -> Result<Vec<u8>, LpmError> {
    let contents = serde_json::to_vec_pretty(manifest)
        .map_err(|e| LpmError::Registry(format!("failed to write package.json: {e}")))?;
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", contents.as_slice())
            .map_err(LpmError::Io)?;
        builder.finish().map_err(LpmError::Io)?;
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&archive).map_err(LpmError::Io)?;
    encoder.finish().map_err(LpmError::Io)
}

/// The npm account the token belongs to.
async fn npm_whoami(
    http: &reqwest::Client,
    registry_url: &str,
    token: &str,
) -> Result<String, LpmError> {
    let url = format!("{}/-/whoami", registry_url.trim_end_matches('/'));
    let response = http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("npm whoami failed: {e}")))?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(LpmError::Registry(
            "npm doesn't accept your npm token. Run `lpm login --npm`, then try again.".into(),
        ));
    }
    if !status.is_success() {
        return Err(LpmError::Registry(format!(
            "npm whoami failed with HTTP {status}"
        )));
    }
    let body = read_capped_json(response).await?;
    body.get("username")
        .and_then(serde_json::Value::as_str)
        .map(str::to_ascii_lowercase)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| LpmError::Registry("npm whoami didn't name an account".into()))
}

async fn read_capped_json(response: reqwest::Response) -> Result<serde_json::Value, LpmError> {
    let bytes = response
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read npm's answer: {e}")))?;
    if bytes.len() > NPM_RESPONSE_MAX_BYTES {
        return Err(LpmError::Registry("npm's answer is too large".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| LpmError::Registry(format!("npm sent an unexpected answer: {e}")))
}

/// The Registry code of a refusal, such as `PACKAGE_NOT_FOUND`.
fn registry_code(error: &LpmError) -> Option<&str> {
    match error {
        LpmError::RegistryHttp(answer) => answer.code.as_deref(),
        _ => None,
    }
}

/// Asks the Registry to check the proof until it finds the package or
/// refuses for another reason. npm can take a few seconds to serve it.
async fn wait_for_proof(
    client: &RegistryClient,
    npm_username: &str,
    wait: Duration,
    interval: Duration,
) -> Result<NpmVerificationResult, LpmError> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let error = match client.npm_verification_verify(npm_username).await {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        let pause = match &error {
            LpmError::RateLimited { retry_after_secs } => Duration::from_secs(*retry_after_secs),
            other if registry_code(other).is_some_and(|code| NOT_YET_CODES.contains(&code)) => {
                interval
            }
            _ => return Err(error),
        };
        if tokio::time::Instant::now() + pause > deadline {
            return Err(error);
        }
        tokio::time::sleep(pause).await;
    }
}

/// Unpublishes the whole proof package, as `npm unpublish <name> --force`
/// does: reads its revision, then deletes that revision. npm asks for the
/// account's second factor here as it does to publish.
async fn unpublish_npm_package(
    http: &reqwest::Client,
    registry_url: &str,
    package_name: &str,
    token: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let registry_url = registry_url.trim_end_matches('/');
    // npm's own escaping of a scoped name: `@scope%2Fname`.
    let encoded = package_name.replacen('/', "%2F", 1);
    let document_url = format!("{registry_url}/{encoded}?write=true");
    let response = http
        .get(&document_url)
        .bearer_auth(token)
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("npm request failed: {e}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    if !response.status().is_success() {
        return Err(LpmError::Registry(format!(
            "npm answered HTTP {} for {package_name}",
            response.status()
        )));
    }
    let document = read_capped_json(response).await?;
    let revision = document
        .get("_rev")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LpmError::Registry(format!("npm sent no revision of {package_name}")))?;
    let delete_url = format!(
        "{registry_url}/{encoded}/-rev/{}",
        urlencoding::encode(revision)
    );

    let delete = |otp: Option<&str>| {
        let mut request = web_auth::add_npm_web_auth_headers(
            http.delete(&delete_url).bearer_auth(token),
            web_auth::NPM_COMMAND_UNPUBLISH,
        );
        if let Some(code) = otp {
            request = request.header("npm-otp", code);
        }
        request.send()
    };
    let response = delete(None)
        .await
        .map_err(|e| LpmError::Network(format!("npm unpublish failed: {e}")))?;
    if response.status().is_success() {
        return Ok(());
    }
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err(LpmError::Registry(format!(
            "npm refused to unpublish {package_name} with HTTP {}",
            response.status()
        )));
    }

    let asks_for_otp = publish_npm::is_otp_required(response.status(), response.headers());
    let body = read_capped_json(response)
        .await
        .unwrap_or(serde_json::Value::Null);
    let otp = if let Some(challenge) =
        web_auth::parse_web_auth_challenge_from_body(&body, registry_url)
    {
        if json_output || !web_auth::terminal_is_interactive() {
            return Err(npm_second_factor_needed(package_name));
        }
        web_auth::complete_web_auth_challenge(
            &challenge,
            "unpublish",
            json_output,
            true,
            Duration::from_secs(5 * 60),
            Duration::from_secs(1),
        )
        .await?
    } else if asks_for_otp {
        if json_output || !web_auth::terminal_is_interactive() {
            return Err(npm_second_factor_needed(package_name));
        }
        publish_npm::prompt_npm_otp()?
    } else {
        return Err(LpmError::Registry(format!(
            "npm refused to unpublish {package_name}: the token may lack permission"
        )));
    };

    let retry = delete(Some(&otp))
        .await
        .map_err(|e| LpmError::Network(format!("npm unpublish failed: {e}")))?;
    if retry.status().is_success() {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "npm refused to unpublish {package_name} with HTTP {}",
            retry.status()
        )))
    }
}

fn npm_second_factor_needed(package_name: &str) -> LpmError {
    LpmError::Registry(format!(
        "npm asks for your second factor to unpublish {package_name}, and this command isn't interactive"
    ))
}

fn report(
    proof: &NpmVerificationResult,
    package_name: &str,
    unpublish_error: Option<&LpmError>,
    json_output: bool,
) {
    let unpublish_command = format!("npm unpublish {package_name} --force");
    if json_output {
        let answer = serde_json::json!({
            "success": true,
            "npmUsername": proof.npm_username,
            "username": proof.username,
            "claimed": proof.claimed,
            "taken": proof.taken,
            "unclaimable": proof.unclaimable,
            "package": package_name,
            "unpublished": unpublish_error.is_none(),
            "unpublishError": unpublish_error.map(ToString::to_string),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&answer).unwrap_or_default()
        );
        return;
    }

    output::success(&format!(
        "Proved the npm account {}",
        lpm_common::sanitize_terminal_inline(&proof.npm_username)
    ));
    if let Some(name) = &proof.claimed {
        install_ui::done_untrusted(&format!("Your username is now {name}"));
    } else if let Some(name) = &proof.taken {
        install_ui::warn_untrusted(&format!(
            "{name} was taken before you finished. Choose another username in your LPM.dev settings."
        ));
    } else if let Some(name) = &proof.unclaimable {
        install_ui::warn_untrusted(&format!(
            "{name} isn't held for this npm account, so you're still waiting for it."
        ));
    }
    match unpublish_error {
        None => install_ui::done_untrusted(&format!("Removed {package_name} from npm")),
        Some(error) => install_ui::warn_untrusted(&format!(
            "Could not remove {package_name} from npm ({error}). Run `{unpublish_command}` within 72 hours."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read as _;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn issued() -> NpmVerificationToken {
        NpmVerificationToken {
            token: "a".repeat(32),
            expires_at: "2026-11-10T12:00:00.000Z".into(),
            package_name: "lpm-verify".into(),
            field: "lpmVerification".into(),
            username: None,
            npm_username: None,
            pending_username: Some("blake-regalia".into()),
            pending_username_npm_accounts: vec!["blake.regalia".into()],
        }
    }

    #[test]
    fn proof_package_holds_only_a_package_json_with_the_token() {
        let manifest = proof_manifest("@blake.regalia/lpm-verify", "1.0.7", &issued());
        let tarball = proof_tarball(&manifest).unwrap();

        let mut archive = tar::Archive::new(GzDecoder::new(tarball.as_slice()));
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().to_str(), Some("package/package.json"));
        let mut contents = String::new();
        entry.read_to_string(&mut contents).unwrap();
        assert!(entries.next().is_none());

        let written: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(written["name"], "@blake.regalia/lpm-verify");
        assert_eq!(written["version"], "1.0.7");
        assert_eq!(written["lpmVerification"], "a".repeat(32));
    }

    #[test]
    fn each_proof_gets_a_version_npm_hasnt_seen() {
        let version = proof_version();
        let patch: u64 = version.strip_prefix("1.0.").unwrap().parse().unwrap();
        assert!(patch > 1_790_000_000);
    }

    #[tokio::test]
    async fn whoami_names_the_npm_account_lowercase() {
        let npm = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/whoami"))
            .and(header("authorization", "Bearer npm_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "username": "TooTallNate"
            })))
            .mount(&npm)
            .await;

        let name = npm_whoami(&npm_http_client().unwrap(), &npm.uri(), "npm_token")
            .await
            .unwrap();
        assert_eq!(name, "tootallnate");
    }

    #[tokio::test]
    async fn whoami_says_to_sign_in_again_when_npm_refuses_the_token() {
        let npm = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/whoami"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&npm)
            .await;

        let error = npm_whoami(&npm_http_client().unwrap(), &npm.uri(), "stale")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lpm login --npm"));
    }

    #[tokio::test]
    async fn unpublish_deletes_the_package_revision() {
        let npm = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@me%2Flpm-verify"))
            .and(query_param("write", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_rev": "3-abc"
            })))
            .mount(&npm)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/@me%2Flpm-verify/-rev/3-abc"))
            .and(header("authorization", "Bearer npm_token"))
            .and(header("npm-command", "unpublish"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })),
            )
            .expect(1)
            .mount(&npm)
            .await;

        unpublish_npm_package(
            &npm_http_client().unwrap(),
            &npm.uri(),
            "@me/lpm-verify",
            "npm_token",
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unpublish_of_a_package_npm_no_longer_has_succeeds() {
        let npm = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@me%2Flpm-verify"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&npm)
            .await;

        unpublish_npm_package(
            &npm_http_client().unwrap(),
            &npm.uri(),
            "@me/lpm-verify",
            "npm_token",
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unpublish_that_needs_a_second_factor_fails_without_a_terminal() {
        let npm = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@me%2Flpm-verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_rev": "1-a"
            })))
            .mount(&npm)
            .await;
        Mock::given(method("DELETE"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("www-authenticate", "OTP required"),
            )
            .mount(&npm)
            .await;

        let error = unpublish_npm_package(
            &npm_http_client().unwrap(),
            &npm.uri(),
            "@me/lpm-verify",
            "npm_token",
            true,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("second factor"));
    }

    fn verify_answer(status: u16, body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(status).set_body_json(body)
    }

    #[tokio::test]
    async fn waits_while_npm_hasnt_served_the_package_then_takes_the_proof() {
        let registry = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-verification/verify"))
            .respond_with(verify_answer(
                422,
                serde_json::json!({ "code": "PACKAGE_NOT_FOUND", "error": "not yet" }),
            ))
            .up_to_n_times(2)
            .mount(&registry)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-verification/verify"))
            .respond_with(verify_answer(
                200,
                serde_json::json!({ "npmUsername": "me", "username": "me", "claimed": "me" }),
            ))
            .expect(1)
            .mount(&registry)
            .await;
        let client = RegistryClient::new()
            .with_base_url(registry.uri())
            .with_token("session-token");

        let proof = wait_for_proof(
            &client,
            "me",
            Duration::from_secs(5),
            Duration::from_millis(5),
        )
        .await
        .unwrap();
        assert_eq!(proof.claimed.as_deref(), Some("me"));
    }

    #[tokio::test]
    async fn stops_at_a_refusal_that_waiting_won_t_change() {
        let registry = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-verification/verify"))
            .respond_with(verify_answer(
                409,
                serde_json::json!({ "code": "NPM_ACCOUNT_LINKED", "error": "linked elsewhere" }),
            ))
            .expect(1)
            .mount(&registry)
            .await;
        let client = RegistryClient::new()
            .with_base_url(registry.uri())
            .with_token("session-token");

        let error = wait_for_proof(
            &client,
            "me",
            Duration::from_secs(5),
            Duration::from_millis(5),
        )
        .await
        .unwrap_err();
        assert_eq!(registry_code(&error), Some("NPM_ACCOUNT_LINKED"));
    }

    #[tokio::test]
    async fn gives_up_waiting_for_npm_after_the_deadline() {
        let registry = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-verification/verify"))
            .respond_with(verify_answer(
                422,
                serde_json::json!({ "code": "TOKEN_NOT_FOUND", "error": "old token" }),
            ))
            .mount(&registry)
            .await;
        let client = RegistryClient::new()
            .with_base_url(registry.uri())
            .with_token("session-token");

        let error = wait_for_proof(
            &client,
            "me",
            Duration::from_millis(30),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(registry_code(&error), Some("TOKEN_NOT_FOUND"));
    }

    #[test]
    fn reads_the_registry_code_of_a_refusal() {
        let refusal = LpmError::RegistryHttp(Box::new(lpm_common::RegistryHttpError {
            status: 422,
            registry: "https://lpm.dev".into(),
            registry_kind: lpm_common::RegistryKind::Lpm,
            code: Some("PACKAGE_NOT_FOUND".into()),
            message: "npm doesn't have the package yet.".into(),
            message_from_registry: true,
            body_kind: lpm_common::RegistryBodyKind::Json,
            request_id: None,
            retry_after_secs: None,
            notice: None,
            subject: None,
        }));
        assert_eq!(registry_code(&refusal), Some("PACKAGE_NOT_FOUND"));
        assert_eq!(registry_code(&LpmError::AuthRequired), None);
    }
}
