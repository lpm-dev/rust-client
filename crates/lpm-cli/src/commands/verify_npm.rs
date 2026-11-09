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
/// Registry codes after which the published package can prove nothing, so
/// it's removed. After any other failure it stays: npm refuses to publish a
/// package for 24 hours after it was unpublished, and "Check npm" in the
/// LPM.dev settings can still find it.
const FINAL_CODES: [&str; 5] = [
    "WRONG_PUBLISHER",
    "PUBLISHED_BEFORE_TOKEN",
    "NPM_ACCOUNT_LINKED",
    "NO_TOKEN",
    "INVALID_NPM_USERNAME",
];
/// The dist-tag of a proof in a package the person already had, so its
/// `latest` stays where it was.
const PROOF_TAG: &str = "lpm-verify";

/// What became of the proof package after the proof.
enum Cleanup {
    Removed,
    Kept,
    Failed(LpmError),
}

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
    // A package of that name the person already had keeps its versions and
    // its `latest`: the proof adds one version and removes only that one.
    let existed = npm_package_document(&http, NPM_REGISTRY_URL, &package_name, npm_token.token())
        .await?
        .is_some();
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
        if existed { PROOF_TAG } else { "latest" },
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

    let cleanup = if proof.is_ok() || proof.as_ref().is_err_and(proof_is_final) {
        if !json_output {
            install_ui::phase_untrusted(&format!("Removing {package_name}@{version} from npm"));
        }
        let removed = if existed {
            unpublish_npm_version(
                &http,
                NPM_REGISTRY_URL,
                &package_name,
                &version,
                npm_token.token(),
                json_output,
            )
            .await
        } else {
            unpublish_npm_package(
                &http,
                NPM_REGISTRY_URL,
                &package_name,
                npm_token.token(),
                json_output,
            )
            .await
        };
        removed.map_or_else(Cleanup::Failed, |()| Cleanup::Removed)
    } else {
        Cleanup::Kept
    };

    match proof {
        Ok(proof) => {
            report(&proof, &package_name, &version, &cleanup, json_output);
            Ok(())
        }
        Err(error) => {
            explain_cleanup_after_failure(&package_name, &npm_username, &cleanup, json_output);
            Err(error)
        }
    }
}

/// Whether a proof failure is one waiting or trying again won't change.
fn proof_is_final(error: &LpmError) -> bool {
    registry_code(error).is_some_and(|code| FINAL_CODES.contains(&code))
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
    if claimants.iter().any(|name| name == npm_username) {
        install_ui::detail_untrusted(&format!(
            "You're waiting for the username {pending}; this proof gives it to you."
        ));
    } else if claimants.is_empty() {
        install_ui::warn_untrusted(&format!(
            "{pending} isn't held for an npm user any more. Choose it again under Account in your LPM.dev settings."
        ));
    } else {
        install_ui::warn_untrusted(&format!(
            "{pending} is held for the npm user {}, but you're signed in to npm as {npm_username}. This proves {npm_username} and leaves {pending} waiting.",
            claimants.join(" or ")
        ));
    }
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
            LpmError::RegistryHttp(answer) if answer.code.as_deref() == Some("RATE_LIMITED") => {
                answer
                    .retry_after_secs
                    .map_or(interval, Duration::from_secs)
            }
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

/// npm's own escaping of a scoped name: `@scope%2Fname`.
fn escaped_npm_name(package_name: &str) -> String {
    package_name.replacen('/', "%2F", 1)
}

/// The package's document as npm keeps it for writes, with its revision,
/// or None when npm has no such package.
async fn npm_package_document(
    http: &reqwest::Client,
    registry_url: &str,
    package_name: &str,
    token: &str,
) -> Result<Option<serde_json::Value>, LpmError> {
    let url = format!(
        "{}/{}?write=true",
        registry_url.trim_end_matches('/'),
        escaped_npm_name(package_name)
    );
    let response = http
        .get(&url)
        .bearer_auth(token)
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("npm request failed: {e}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(LpmError::Registry(format!(
            "npm answered HTTP {} for {package_name}",
            response.status()
        )));
    }
    read_capped_json(response).await.map(Some)
}

fn revision_of(document: &serde_json::Value, package_name: &str) -> Result<String, LpmError> {
    document
        .get("_rev")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| LpmError::Registry(format!("npm sent no revision of {package_name}")))
}

/// Sends an npm write, answering npm's ask for the account's second factor
/// once and keeping the code for the writes after it.
async fn send_npm_write(
    request: impl Fn(Option<&str>) -> reqwest::RequestBuilder,
    registry_url: &str,
    package_name: &str,
    otp: &mut Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    let send = |code: Option<&str>| {
        let request = request(code);
        async move {
            request
                .send()
                .await
                .map_err(|e| LpmError::Network(format!("npm request failed: {e}")))
        }
    };
    let response = send(otp.as_deref()).await?;
    if response.status().is_success() {
        return Ok(());
    }
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err(npm_write_refused(package_name, response.status()));
    }

    let asks_for_otp = publish_npm::is_otp_required(response.status(), response.headers());
    let body = read_capped_json(response)
        .await
        .unwrap_or(serde_json::Value::Null);
    let challenge = web_auth::parse_web_auth_challenge_from_body(&body, registry_url);
    if challenge.is_none() && !asks_for_otp {
        return Err(LpmError::Registry(format!(
            "npm refused to change {package_name}: the token may lack permission"
        )));
    }
    if json_output || !web_auth::terminal_is_interactive() {
        return Err(LpmError::Registry(format!(
            "npm asks for your second factor to change {package_name}, and this command isn't interactive"
        )));
    }
    let code = match challenge {
        Some(challenge) => {
            web_auth::complete_web_auth_challenge(
                &challenge,
                "unpublish",
                json_output,
                true,
                Duration::from_secs(5 * 60),
                Duration::from_secs(1),
            )
            .await?
        }
        None => publish_npm::prompt_npm_otp()?,
    };
    let retry = send(Some(&code)).await?;
    *otp = Some(code);
    if retry.status().is_success() {
        Ok(())
    } else {
        Err(npm_write_refused(package_name, retry.status()))
    }
}

fn npm_write_refused(package_name: &str, status: reqwest::StatusCode) -> LpmError {
    LpmError::Registry(format!(
        "npm refused to change {package_name} with HTTP {status}"
    ))
}

/// Unpublishes the whole proof package, as `npm unpublish <name> --force`
/// does: reads its revision, then deletes that revision.
async fn unpublish_npm_package(
    http: &reqwest::Client,
    registry_url: &str,
    package_name: &str,
    token: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let Some(document) = npm_package_document(http, registry_url, package_name, token).await?
    else {
        return Ok(());
    };
    let revision = revision_of(&document, package_name)?;
    let url = format!(
        "{}/{}/-rev/{}",
        registry_url.trim_end_matches('/'),
        escaped_npm_name(package_name),
        urlencoding::encode(&revision)
    );
    send_npm_write(
        |otp| npm_write(http.delete(&url), token, otp),
        registry_url,
        package_name,
        &mut None,
        json_output,
    )
    .await
}

/// Unpublishes one version of a package that keeps others, as
/// `npm unpublish <name>@<version>` does: writes the document without the
/// version and the tags that named it, then deletes the version's tarball.
/// Only the registry's own host gets the token.
async fn unpublish_npm_version(
    http: &reqwest::Client,
    registry_url: &str,
    package_name: &str,
    version: &str,
    token: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let registry_url = registry_url.trim_end_matches('/');
    let Some(mut document) = npm_package_document(http, registry_url, package_name, token).await?
    else {
        return Ok(());
    };
    let Some(versions) = document
        .get_mut("versions")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Err(LpmError::Registry(format!(
            "npm sent no versions of {package_name}"
        )));
    };
    let Some(removed) = versions.remove(version) else {
        return Ok(());
    };
    if versions.is_empty() {
        return unpublish_npm_package(http, registry_url, package_name, token, json_output).await;
    }
    let remaining_highest = versions
        .keys()
        .filter_map(|key| {
            lpm_semver::Version::parse(key)
                .ok()
                .map(|parsed| (parsed, key.clone()))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, key)| key);
    if let Some(tags) = document
        .get_mut("dist-tags")
        .and_then(serde_json::Value::as_object_mut)
    {
        let was_latest = tags.get("latest").and_then(serde_json::Value::as_str) == Some(version);
        tags.retain(|_, target| target.as_str() != Some(version));
        if was_latest && let Some(highest) = remaining_highest {
            tags.insert("latest".into(), serde_json::Value::String(highest));
        }
    }
    if let Some(object) = document.as_object_mut() {
        object.remove("_revisions");
        object.remove("_attachments");
    }
    let tarball_path = removed
        .pointer("/dist/tarball")
        .and_then(serde_json::Value::as_str)
        .and_then(|tarball| reqwest::Url::parse(tarball).ok())
        .map(|tarball| tarball.path().to_owned())
        .ok_or_else(|| {
            LpmError::Registry(format!("npm sent no tarball for {package_name}@{version}"))
        })?;

    let mut otp = None;
    let revision = revision_of(&document, package_name)?;
    let document_url = format!(
        "{registry_url}/{}/-rev/{}",
        escaped_npm_name(package_name),
        urlencoding::encode(&revision)
    );
    send_npm_write(
        |code| npm_write(http.put(&document_url).json(&document), token, code),
        registry_url,
        package_name,
        &mut otp,
        json_output,
    )
    .await?;

    let Some(updated) = npm_package_document(http, registry_url, package_name, token).await? else {
        return Ok(());
    };
    let tarball_url = format!(
        "{registry_url}{tarball_path}/-rev/{}",
        urlencoding::encode(&revision_of(&updated, package_name)?)
    );
    send_npm_write(
        |code| npm_write(http.delete(&tarball_url), token, code),
        registry_url,
        package_name,
        &mut otp,
        json_output,
    )
    .await
}

fn npm_write(
    request: reqwest::RequestBuilder,
    token: &str,
    otp: Option<&str>,
) -> reqwest::RequestBuilder {
    let request = web_auth::add_npm_web_auth_headers(
        request.bearer_auth(token),
        web_auth::NPM_COMMAND_UNPUBLISH,
    );
    match otp {
        Some(code) => request.header("npm-otp", code),
        None => request,
    }
}

/// After a failed proof, what became of the package and what to do next.
/// With `--json` it goes to stderr, so stdout keeps the error alone.
fn explain_cleanup_after_failure(
    package_name: &str,
    npm_username: &str,
    cleanup: &Cleanup,
    json_output: bool,
) {
    let unpublish = format!("npm unpublish {package_name} --force");
    let advice = match cleanup {
        Cleanup::Removed => return,
        Cleanup::Kept => format!(
            "LPM.dev couldn't confirm the proof yet, so {package_name} stays on npm. To finish without publishing again, select \"Check npm\" under npm account in your LPM.dev settings with the npm username {npm_username} within 24 hours. Then run `{unpublish}`."
        ),
        Cleanup::Failed(error) => format!(
            "Could not remove {package_name} from npm ({error}). Run `{unpublish}` within 72 hours."
        ),
    };
    if json_output {
        eprintln!("{}", lpm_common::sanitize_terminal_inline(&advice));
    } else {
        install_ui::warn_untrusted(&advice);
    }
}

fn report(
    proof: &NpmVerificationResult,
    package_name: &str,
    version: &str,
    cleanup: &Cleanup,
    json_output: bool,
) {
    let unpublish_error = match cleanup {
        Cleanup::Failed(error) => Some(error),
        Cleanup::Removed | Cleanup::Kept => None,
    };
    if json_output {
        let answer = serde_json::json!({
            "success": true,
            "npmUsername": proof.npm_username,
            "username": proof.username,
            "claimed": proof.claimed,
            "taken": proof.taken,
            "unclaimable": proof.unclaimable,
            "locked": proof.locked,
            "package": package_name,
            "version": version,
            "unpublished": matches!(cleanup, Cleanup::Removed),
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
    } else if let Some(name) = &proof.locked {
        install_ui::warn_untrusted(&format!(
            "You published under your current username, so it can't change to {name} any more."
        ));
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
        None => install_ui::done_untrusted(&format!("Removed {package_name}@{version} from npm")),
        Some(error) => install_ui::warn_untrusted(&format!(
            "Could not remove {package_name}@{version} from npm ({error}). Run `npm unpublish {package_name}@{version}` within 72 hours."
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

    #[tokio::test]
    async fn removing_a_proof_from_a_package_the_person_had_keeps_their_versions_and_latest() {
        let npm = MockServer::start().await;
        let tarball = format!("{}/@me/lpm-verify/-/lpm-verify-1.0.99.tgz", npm.uri());
        Mock::given(method("GET"))
            .and(path("/@me%2Flpm-verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_id": "@me/lpm-verify",
                "_rev": "5-a",
                "dist-tags": { "latest": "1.0.0", "lpm-verify": "1.0.99" },
                "versions": {
                    "1.0.0": { "dist": { "tarball": "https://registry.npmjs.org/@me/lpm-verify/-/lpm-verify-1.0.0.tgz" } },
                    "1.0.99": { "dist": { "tarball": tarball } },
                },
                "_attachments": {},
            })))
            .up_to_n_times(1)
            .mount(&npm)
            .await;
        Mock::given(method("GET"))
            .and(path("/@me%2Flpm-verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_rev": "6-b",
            })))
            .mount(&npm)
            .await;
        Mock::given(method("PUT"))
            .and(path("/@me%2Flpm-verify/-rev/5-a"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&npm)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/@me/lpm-verify/-/lpm-verify-1.0.99.tgz/-rev/6-b"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&npm)
            .await;

        unpublish_npm_version(
            &npm_http_client().unwrap(),
            &npm.uri(),
            "@me/lpm-verify",
            "1.0.99",
            "npm_token",
            true,
        )
        .await
        .unwrap();

        let requests = npm.received_requests().await.unwrap();
        let written = requests
            .iter()
            .find(|request| request.method == wiremock::http::Method::PUT)
            .unwrap();
        let document: serde_json::Value = serde_json::from_slice(&written.body).unwrap();
        assert_eq!(
            document["versions"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["1.0.0"]
        );
        assert_eq!(
            document["dist-tags"],
            serde_json::json!({ "latest": "1.0.0" })
        );
        assert!(document.get("_attachments").is_none());
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() != "/@me%2Flpm-verify/-rev/5-a"
                    || request.method != wiremock::http::Method::DELETE)
        );
    }

    #[tokio::test]
    async fn removing_the_only_version_unpublishes_the_package() {
        let npm = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@me%2Flpm-verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_rev": "2-c",
                "versions": { "1.0.99": { "dist": { "tarball": "https://registry.npmjs.org/x.tgz" } } },
            })))
            .mount(&npm)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/@me%2Flpm-verify/-rev/2-c"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&npm)
            .await;

        unpublish_npm_version(
            &npm_http_client().unwrap(),
            &npm.uri(),
            "@me/lpm-verify",
            "1.0.99",
            "npm_token",
            true,
        )
        .await
        .unwrap();
    }

    #[test]
    fn removes_the_package_only_after_a_refusal_that_trying_again_won_t_change() {
        let refusal = |code: &str| {
            LpmError::RegistryHttp(Box::new(lpm_common::RegistryHttpError {
                status: 422,
                registry: "https://lpm.dev".into(),
                registry_kind: lpm_common::RegistryKind::Lpm,
                code: Some(code.into()),
                message: String::new(),
                message_from_registry: true,
                body_kind: lpm_common::RegistryBodyKind::Json,
                request_id: None,
                retry_after_secs: None,
                notice: None,
                subject: None,
            }))
        };
        for code in ["WRONG_PUBLISHER", "NPM_ACCOUNT_LINKED", "NO_TOKEN"] {
            assert!(proof_is_final(&refusal(code)), "{code}");
        }
        for code in [
            "PACKAGE_NOT_FOUND",
            "TOKEN_NOT_FOUND",
            "NPM_UNAVAILABLE",
            "RATE_LIMITED",
        ] {
            assert!(!proof_is_final(&refusal(code)), "{code}");
        }
        assert!(!proof_is_final(&LpmError::Network("timed out".into())));
    }

    #[tokio::test]
    async fn waits_out_the_registry_s_rate_limit() {
        let registry = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-verification/verify"))
            .respond_with(
                verify_answer(
                    429,
                    serde_json::json!({ "code": "RATE_LIMITED", "error": "Too many checks." }),
                )
                .insert_header("retry-after", "1"),
            )
            .up_to_n_times(1)
            .mount(&registry)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-verification/verify"))
            .respond_with(verify_answer(
                200,
                serde_json::json!({ "npmUsername": "me", "username": "me", "claimed": "me" }),
            ))
            .mount(&registry)
            .await;
        let client = RegistryClient::new()
            .with_base_url(registry.uri())
            .with_token("session-token");

        let proof = wait_for_proof(
            &client,
            "me",
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await
        .unwrap();
        assert_eq!(proof.claimed.as_deref(), Some("me"));
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
