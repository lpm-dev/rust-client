//! Socket's package verdicts, which a user can turn on with
//! `[skills] security-provider = "socket"` to check the npm packages that
//! ship skills before LPM links them. Only [`super::checks`] asks, outside
//! every lock; planning reads the verdicts it recorded.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

const DEFAULT_API: &str = "https://api.socket.dev/v0";
/// The variable that points LPM at another Socket API.
pub(crate) const API_OVERRIDE_VARIABLE: &str = "LPM_SOCKET_API_URL";
/// The most PURLs one request may name.
const MAX_PURLS_PER_REQUEST: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest one round of asking may take, all requests together.
const ROUND_DEADLINE: Duration = Duration::from_secs(60);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ORGANIZATIONS_BYTES: usize = 1024 * 1024;
/// The alert types that mean Socket considers the version malware.
const MALWARE_ALERTS: [&str; 2] = ["malware", "gptMalware"];
/// What every package lookup asks for: alerts in the compact shape, a
/// synthetic `notFound` alert for each version Socket has no record of
/// (which needs `purlErrors`), and the current state at once instead of a
/// wait for analysis to finish.
const LOOKUP_QUERY: &str =
    "alerts=true&compact=true&purlErrors=true&notFoundAlerts=true&poll=false";

/// What Socket says about one package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Verdict {
    Clean,
    /// A known or AI-detected malware alert.
    Malware {
        alert: String,
    },
    /// Socket hasn't finished analyzing the version.
    Pending,
    /// Socket has no record of the version, or gave no usable answer.
    Unknown,
}

impl Verdict {
    /// How strongly the verdict holds the version back, so that of two
    /// answers about one version the stricter wins.
    pub(crate) fn strictness(&self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Unknown => 1,
            Self::Pending => 2,
            Self::Malware { .. } => 3,
        }
    }
}

/// Why Socket couldn't answer, and the wait it asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) reason: String,
    /// Socket's `Retry-After`, when it named one.
    pub(crate) retry_after: Option<Duration>,
    /// Found on this machine before asking, such as a missing token: never
    /// recorded for other projects; the links look again when a verdict
    /// they rest on expires, or a day on at the latest.
    pub(crate) local: bool,
    /// Found on this machine and likely to pass, such as a runtime that
    /// couldn't start: the links look again after the usual wait.
    pub(crate) transient: bool,
}

impl Failure {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            retry_after: None,
            local: false,
            transient: false,
        }
    }

    fn local(reason: impl Into<String>) -> Self {
        Self {
            local: true,
            ..Self::new(reason)
        }
    }

    fn transient(reason: impl Into<String>) -> Self {
        Self {
            transient: true,
            ..Self::local(reason)
        }
    }
}

/// What Socket said about one version, and when the answer arrived, in
/// milliseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observed {
    pub(crate) verdict: Verdict,
    pub(crate) at_ms: u64,
}

/// What one round of asking produced: a verdict for every version Socket
/// answered for, and why it stopped answering, if it did. Versions of a
/// batch after a failure go unanswered; earlier batches keep theirs.
#[derive(Debug)]
pub(crate) struct Answers {
    pub(crate) verdicts: HashMap<(String, String), Observed>,
    pub(crate) failure: Option<Failure>,
    /// When the round ended, in milliseconds since the Unix epoch.
    pub(crate) at_ms: u64,
}

impl Answers {
    pub(crate) fn failed(failure: Failure) -> Self {
        Self {
            verdicts: HashMap::new(),
            failure: Some(failure),
            at_ms: super::checks::now_ms(),
        }
    }
}

/// Where LPM asks Socket, and the token it asks with.
pub(crate) struct Endpoint {
    base: String,
    token: SecretString,
}

impl Endpoint {
    /// Socket's API with the user's Socket token. An `LPM_SOCKET_API_URL`
    /// override gets only a token from the environment: the token LPM
    /// stores goes to Socket's own API and nowhere else.
    pub(crate) fn resolve() -> Result<Self, Failure> {
        let base = api_override().map_err(Failure::local)?;
        let Some(credential) = lpm_auth::resolve_socket_credential() else {
            return Err(Failure::local(
                "no Socket API token; run `lpm login --socket` or set SOCKET_CLI_API_TOKEN",
            ));
        };
        if base.is_some()
            && matches!(
                credential.source(),
                lpm_auth::ThirdPartyCredentialSource::Stored(_)
            )
        {
            return Err(Failure::local(format!(
                "{API_OVERRIDE_VARIABLE} points away from Socket's API, and LPM sends the Socket token it stores only to Socket; set SOCKET_CLI_API_TOKEN for that endpoint"
            )));
        }
        let carries = credential.with_exposed_token(|token| {
            token
                .bytes()
                .all(|byte| byte == b'\t' || !(byte < 0x20 || byte == 0x7f))
        });
        if !carries {
            return Err(Failure::local(
                "the Socket API token holds a control character, such as a newline, that an HTTP header can't carry",
            ));
        }
        Ok(Self {
            base: base.unwrap_or_else(|| DEFAULT_API.to_string()),
            token: SecretString::from(credential.with_exposed_token(str::to_owned)),
        })
    }

    /// The API to check `token` against, as `lpm login --socket` does.
    fn for_token(token: &str) -> Result<Self, String> {
        Ok(Self {
            base: api_override()?.unwrap_or_else(|| DEFAULT_API.to_string()),
            token: SecretString::from(token.to_owned()),
        })
    }
}

/// The `LPM_SOCKET_API_URL` override without its trailing slash, `None`
/// when unset, or why it can't be used: only HTTPS, or HTTP to a loopback
/// address, without credentials, a query or a fragment.
fn api_override() -> Result<Option<String>, String> {
    let Some(url) = std::env::var(API_OVERRIDE_VARIABLE)
        .ok()
        .filter(|url| !url.is_empty())
    else {
        return Ok(None);
    };
    let acceptable = crate::release_lookup::accept_override(&url)
        && reqwest::Url::parse(&url)
            .is_ok_and(|parsed| parsed.query().is_none() && parsed.fragment().is_none());
    if !acceptable {
        return Err(format!(
            "{API_OVERRIDE_VARIABLE} must be an HTTPS URL, or HTTP to a loopback address, without credentials, a query or a fragment"
        ));
    }
    Ok(Some(url.trim_end_matches('/').to_string()))
}

fn client() -> Result<reqwest::Client, String> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| format!("the Socket client could not be built: {error}"))
}

/// The slug of the organization `token` belongs to, for `lpm login
/// --socket`.
pub(crate) async fn login_organization(token: &str) -> Result<String, String> {
    let endpoint = endpoint_for_login(token, cfg!(debug_assertions))?;
    organization(&client()?, &endpoint, deadline())
        .await
        .map_err(|failure| failure.reason)
}

/// Where `lpm login --socket` checks `token`: Socket's own API, since the
/// token it stores goes nowhere else. Only a debug build, for tests, may
/// check it with the `LPM_SOCKET_API_URL` override.
fn endpoint_for_login(token: &str, allow_override: bool) -> Result<Endpoint, String> {
    if !allow_override && api_override()?.is_some() {
        return Err(format!(
            "{API_OVERRIDE_VARIABLE} is set, and LPM checks the Socket token it stores only with Socket's own API; unset it to log in, or set SOCKET_CLI_API_TOKEN for that endpoint instead"
        ));
    }
    Endpoint::for_token(token)
}

/// The name of the file that keeps verdicts from the API LPM asks now:
/// Socket's own, an override's, or none for an override LPM can't use, so
/// answers from one never stand in for another's.
pub(crate) fn cache_scope() -> Option<String> {
    use sha2::{Digest as _, Sha256};
    match api_override() {
        Ok(None) => Some("socket".to_string()),
        Ok(Some(url)) => Some(format!(
            "socket-{}",
            &hex::encode(Sha256::digest(url.as_bytes()))[..16]
        )),
        Err(_) => None,
    }
}

/// When one round of asking must be over: past it, the versions not
/// answered yet wait for a later install, and earlier answers stand.
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + ROUND_DEADLINE
}

async fn organization(
    client: &reqwest::Client,
    endpoint: &Endpoint,
    deadline: tokio::time::Instant,
) -> Result<String, Failure> {
    let response = client
        .get(format!("{}/organizations", endpoint.base))
        .bearer_auth(endpoint.token.expose_secret())
        .timeout(remaining(deadline)?)
        .send()
        .await
        .map_err(unreachable)?;
    let body = read_body(response, MAX_ORGANIZATIONS_BYTES).await?;
    let parsed: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
        Failure::new(format!(
            "Socket returned an unreadable organization list: {error}"
        ))
    })?;
    let mut slugs: Vec<&str> = parsed
        .get("organizations")
        .and_then(serde_json::Value::as_object)
        .map(|organizations| {
            organizations
                .values()
                .filter_map(|organization| organization.get("slug")?.as_str())
                .collect()
        })
        .unwrap_or_default();
    if !slugs.iter().all(|slug| is_organization_slug(slug)) {
        return Err(Failure::new(
            "Socket named an organization whose slug LPM won't put in a URL",
        ));
    }
    slugs.sort_unstable();
    match slugs.as_slice() {
        [slug] => Ok((*slug).to_string()),
        [] => Err(Failure::new("the Socket token belongs to no organization")),
        _ => Err(Failure::new(format!(
            "the Socket token belongs to several organizations ({}); use an organization token",
            slugs.join(", ")
        ))),
    }
}

/// Whether `slug` looks like a Socket organization slug: letters, digits,
/// `-`, `_` and `.`, not starting with a dot.
fn is_organization_slug(slug: &str) -> bool {
    (1..=128).contains(&slug.len())
        && !slug.starts_with('.')
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

/// Socket's verdicts for `packages`, npm names and versions, from
/// synchronous code: the requests run on a runtime of their own while the
/// caller waits.
pub(crate) fn lookup(endpoint: &Endpoint, packages: &[(String, String)]) -> Answers {
    block_on(async {
        lookup_in_batches(endpoint, packages, MAX_PURLS_PER_REQUEST, deadline()).await
    })
    .unwrap_or_else(|reason| Answers::failed(Failure::transient(reason)))
}

async fn lookup_in_batches(
    endpoint: &Endpoint,
    packages: &[(String, String)],
    batch_size: usize,
    deadline: tokio::time::Instant,
) -> Result<Answers, String> {
    let client = client()?;
    let organization = match organization(&client, endpoint, deadline).await {
        Ok(organization) => organization,
        Err(failure) => return Ok(Answers::failed(failure)),
    };
    let mut answers = Answers {
        verdicts: HashMap::with_capacity(packages.len()),
        failure: None,
        at_ms: 0,
    };
    let url = format!(
        "{}/orgs/{}/purl?{LOOKUP_QUERY}",
        endpoint.base,
        urlencoding::encode(&organization)
    );
    for batch in packages.chunks(batch_size) {
        let purls: Vec<String> = batch
            .iter()
            .map(|(name, version)| lpm_common::npm_package_purl(name, version))
            .collect();
        let body = serde_json::json!({
            "components": purls.iter().map(|purl| serde_json::json!({ "purl": purl })).collect::<Vec<_>>(),
        });
        let answer = match remaining(deadline) {
            Ok(timeout) => match client
                .post(&url)
                .bearer_auth(endpoint.token.expose_secret())
                .timeout(timeout)
                .json(&body)
                .send()
                .await
            {
                Ok(response) => read_body(response, MAX_RESPONSE_BYTES).await,
                Err(error) => Err(unreachable(error)),
            },
            Err(failure) => Err(failure),
        };
        match answer {
            Ok(answer) => {
                let at_ms = super::checks::now_ms();
                for (package, verdict) in batch.iter().zip(parse_answer(&answer, batch)) {
                    answers
                        .verdicts
                        .insert(package.clone(), Observed { verdict, at_ms });
                }
            }
            Err(failure) => {
                answers.failure = Some(failure);
                break;
            }
        }
    }
    answers.at_ms = super::checks::now_ms();
    Ok(answers)
}

/// The time left before `deadline` for one request, at most the usual
/// request timeout, or the failure once none is left.
fn remaining(deadline: tokio::time::Instant) -> Result<Duration, Failure> {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    if left.is_zero() {
        return Err(Failure::new(format!(
            "Socket didn't answer within {} seconds",
            ROUND_DEADLINE.as_secs()
        )));
    }
    Ok(left.min(REQUEST_TIMEOUT))
}

/// Why a request failed: one that couldn't even be built never left this
/// machine, so it is a failure found here.
fn unreachable(error: reqwest::Error) -> Failure {
    if error.is_builder() {
        return Failure::local(format!(
            "LPM couldn't build a request to Socket: {}",
            lpm_http::display_error(&error)
        ));
    }
    Failure::new(format!(
        "Socket could not be reached: {}",
        lpm_http::display_error(&error)
    ))
}

async fn read_body(response: reqwest::Response, cap: usize) -> Result<Vec<u8>, Failure> {
    let status = response.status();
    match status {
        reqwest::StatusCode::UNAUTHORIZED => Err(Failure::new("Socket rejected the API token")),
        reqwest::StatusCode::FORBIDDEN => Err(Failure::new(
            "Socket refused the lookup: the token needs the packages:list scope, on an organization plan that allows package lookups",
        )),
        reqwest::StatusCode::TOO_MANY_REQUESTS => Err(Failure {
            reason: "Socket's rate limit or API quota for the organization is used up for now"
                .into(),
            local: false,
            transient: false,
            retry_after: response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
        }),
        status if !status.is_success() => Err(Failure::new(format!("Socket answered {status}"))),
        _ => lpm_http::read_body_capped(response, cap)
            .await
            .map_err(|error| Failure::new(format!("Socket's answer could not be read: {error}"))),
    }
}

/// The verdict for each of `batch`, in its order, from Socket's
/// newline-delimited answer. A row counts for the version its `inputPurl`
/// names or, since compact answers may leave that out, the version its
/// `type`, `namespace`, `name` and `version` name, and when it gives both
/// they must agree. A row without an `alerts` array, or with an alert that
/// has no type, and a version no row answers for, are [`Verdict::Unknown`]
/// unless a malware alert or a pending scan decides it; of several answers
/// for one version the strictest wins.
fn parse_answer(body: &[u8], batch: &[(String, String)]) -> Vec<Verdict> {
    let positions: HashMap<String, usize> = batch
        .iter()
        .enumerate()
        .map(|(position, (name, version))| (lpm_common::npm_package_purl(name, version), position))
        .collect();
    let mut verdicts: Vec<Option<Verdict>> = vec![None; batch.len()];
    for line in body.split(|byte| *byte == b'\n') {
        let Ok(row) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let answered = match row.get("_type").and_then(serde_json::Value::as_str) {
            Some("purlError") => row.get("value").and_then(|value| {
                let position = positions.get(value.get("inputPurl")?.as_str()?)?;
                let retryable = value
                    .get("retryable")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                Some((
                    *position,
                    if retryable {
                        Verdict::Pending
                    } else {
                        Verdict::Unknown
                    },
                ))
            }),
            Some(_) => None,
            None => {
                artifact_position(&row, &positions).map(|position| (position, verdict_of(&row)))
            }
        };
        if let Some((position, verdict)) = answered {
            let slot = &mut verdicts[position];
            if slot
                .as_ref()
                .is_none_or(|current| verdict.strictness() > current.strictness())
            {
                *slot = Some(verdict);
            }
        }
    }
    verdicts
        .into_iter()
        .map(|verdict| verdict.unwrap_or(Verdict::Unknown))
        .collect()
}

/// How an artifact row names the release it answers for, by one of its two
/// identities.
enum Identity {
    Absent,
    /// Present, but not a well-formed npm release.
    Invalid,
    Purl(String),
}

/// The position in the batch of the version an artifact row answers for:
/// the one its `inputPurl` names and, when the row also names a release by
/// its coordinates, that same one; else the one its coordinates name. A
/// row with an identity that is malformed, partial or of another ecosystem
/// answers for nothing.
fn artifact_position(row: &serde_json::Value, positions: &HashMap<String, usize>) -> Option<usize> {
    match (input_identity(row), coordinates_identity(row)) {
        (Identity::Purl(input), Identity::Purl(coordinates)) => {
            let position = positions.get(&input)?;
            (positions.get(&coordinates) == Some(position)).then_some(*position)
        }
        (Identity::Purl(purl), Identity::Absent) | (Identity::Absent, Identity::Purl(purl)) => {
            positions.get(&purl).copied()
        }
        _ => None,
    }
}

fn input_identity(row: &serde_json::Value) -> Identity {
    match row.get("inputPurl") {
        None | Some(serde_json::Value::Null) => Identity::Absent,
        Some(serde_json::Value::String(purl)) => Identity::Purl(purl.clone()),
        Some(_) => Identity::Invalid,
    }
}

/// The npm release an artifact row's `type`, `namespace`, `name` and
/// `version` name. A row claims coordinates with any of `type`, `name` or
/// `version`, even null, or a non-null `namespace`, and then every one it
/// needs must be a string.
fn coordinates_identity(row: &serde_json::Value) -> Identity {
    let claimed = ["type", "name", "version"]
        .iter()
        .any(|key| row.get(key).is_some())
        || row.get("namespace").is_some_and(|value| !value.is_null());
    if !claimed {
        return Identity::Absent;
    }
    let field = |key: &str| match row.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(()),
    };
    let (Ok(Some("npm")), Ok(namespace), Ok(Some(name)), Ok(Some(version))) = (
        field("type"),
        field("namespace"),
        field("name"),
        field("version"),
    ) else {
        return Identity::Invalid;
    };
    let package = match namespace.filter(|namespace| !namespace.is_empty()) {
        Some(namespace) => {
            let scope = namespace
                .strip_prefix("%40")
                .or_else(|| namespace.strip_prefix('@'))
                .unwrap_or(namespace);
            format!("@{scope}/{name}")
        }
        None => name.to_string(),
    };
    Identity::Purl(lpm_common::npm_package_purl(&package, version))
}

fn verdict_of(row: &serde_json::Value) -> Verdict {
    let Some(alerts) = row.get("alerts").and_then(serde_json::Value::as_array) else {
        return Verdict::Unknown;
    };
    let types: Vec<Option<&str>> = alerts
        .iter()
        .map(|alert| {
            alert
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|kind| !kind.is_empty())
        })
        .collect();
    if let Some(malware) = types
        .iter()
        .flatten()
        .find(|kind| MALWARE_ALERTS.contains(kind))
    {
        Verdict::Malware {
            alert: (*malware).to_string(),
        }
    } else if types.contains(&Some("pendingScan")) {
        Verdict::Pending
    } else if types.contains(&None) || types.contains(&Some("notFound")) {
        Verdict::Unknown
    } else {
        Verdict::Clean
    }
}

fn block_on<T: Send>(future: impl Future<Output = Result<T, String>> + Send) -> Result<T, String> {
    let run = || {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| format!("the Socket check could not start: {error}"))?
                        .block_on(future)
                })
                .join()
                .unwrap_or_else(|_| Err("the Socket check stopped unexpectedly".into()))
        })
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(run)
        }
        _ => run(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(packages: &[(&str, &str)]) -> Vec<(String, String)> {
        packages
            .iter()
            .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
            .collect()
    }

    fn malware(alert: &str) -> Verdict {
        Verdict::Malware {
            alert: alert.into(),
        }
    }

    #[test]
    fn malware_alerts_win_and_synthetic_alerts_mark_pending_and_unknown_versions() {
        let packages = batch(&[
            ("clean", "1.0.0"),
            ("bad", "1.0.0"),
            ("new", "1.0.0"),
            ("@acme/private", "1.0.0"),
        ]);
        let body = [
            r#"{"inputPurl":"pkg:npm/clean@1.0.0","alerts":[{"type":"envVars","key":"a"}]}"#,
            r#"{"inputPurl":"pkg:npm/bad@1.0.0","alerts":[{"type":"pendingScan"},{"type":"gptMalware"}]}"#,
            r#"{"inputPurl":"pkg:npm/new@1.0.0","alerts":[{"type":"pendingScan"}]}"#,
            r#"{"inputPurl":"pkg:npm/%40acme/private@1.0.0","alerts":[{"type":"notFound"}]}"#,
            r#"{"_type":"summary","value":{}}"#,
            "not json",
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [
                Verdict::Clean,
                malware("gptMalware"),
                Verdict::Pending,
                Verdict::Unknown
            ]
        );
    }

    #[test]
    fn a_row_without_an_alerts_array_and_a_version_without_a_row_are_unknown() {
        let packages = batch(&[("bare", "1.0.0"), ("odd", "1.0.0"), ("missing", "1.0.0")]);
        let body = [
            r#"{"type":"npm","name":"bare","version":"1.0.0"}"#,
            r#"{"type":"npm","name":"odd","version":"1.0.0","alerts":{"type":"envVars"}}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [Verdict::Unknown, Verdict::Unknown, Verdict::Unknown]
        );
    }

    #[test]
    fn a_later_row_for_the_same_version_never_softens_an_earlier_verdict() {
        let packages = batch(&[("tool", "1.0.0")]);
        let body = [
            r#"{"type":"npm","name":"tool","version":"1.0.0","alerts":[{"type":"malware"}]}"#,
            r#"{"type":"npm","name":"tool","version":"1.0.0","alerts":[]}"#,
            r#"{"type":"npm","name":"tool","version":"1.0.0","alerts":[{"type":"pendingScan"}]}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [malware("malware")]
        );
    }

    #[test]
    fn rows_without_an_input_purl_match_by_namespace_name_and_version() {
        let packages = batch(&[("@acme/tool", "2.0.0"), ("plain", "1.0.0")]);
        let body = [
            r#"{"type":"npm","namespace":"@acme","name":"tool","version":"2.0.0","alerts":[]}"#,
            r#"{"type":"npm","name":"plain","version":"1.0.0","alerts":[{"type":"malware"}]}"#,
            r#"{"type":"pypi","name":"plain","version":"1.0.0","alerts":[]}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [Verdict::Clean, malware("malware")]
        );
    }

    #[test]
    fn a_malformed_alert_or_a_row_naming_another_release_never_reads_as_clean() {
        let packages = batch(&[("odd", "1.0.0"), ("other", "1.0.0"), ("flagged", "1.0.0")]);
        let body = [
            r#"{"type":"npm","name":"odd","version":"1.0.0","alerts":[{"kind":"malware"},{"type":"envVars"}]}"#,
            r#"{"inputPurl":"pkg:npm/other@1.0.0","type":"npm","name":"somebody-else","version":"9.9.9","alerts":[]}"#,
            r#"{"type":"npm","name":"flagged","version":"1.0.0","alerts":[{"type":null},{"type":"malware"}]}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [Verdict::Unknown, Verdict::Unknown, malware("malware")]
        );
    }

    #[test]
    fn a_row_whose_identity_is_invalid_partial_or_contradictory_answers_for_nothing() {
        let packages = batch(&[
            ("pypi", "1.0.0"),
            ("partial", "1.0.0"),
            ("requested", "1.0.0"),
            ("numbered", "1.0.0"),
            ("unscoped", "1.0.0"),
        ]);
        let body = [
            r#"{"inputPurl":"pkg:npm/pypi@1.0.0","type":"pypi","name":"pypi","version":"1.0.0","alerts":[]}"#,
            r#"{"inputPurl":"pkg:npm/partial@1.0.0","type":"npm","name":"partial","alerts":[]}"#,
            r#"{"inputPurl":"pkg:npm/unrequested@1.0.0","type":"npm","name":"requested","version":"1.0.0","alerts":[]}"#,
            r#"{"inputPurl":7,"type":"npm","name":"numbered","version":"1.0.0","alerts":[]}"#,
            r#"{"type":"npm","namespace":7,"name":"unscoped","version":"1.0.0","alerts":[]}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [
                Verdict::Unknown,
                Verdict::Unknown,
                Verdict::Unknown,
                Verdict::Unknown,
                Verdict::Unknown
            ]
        );
    }

    #[test]
    fn null_identity_fields_and_blank_alert_types_never_read_as_clean() {
        let packages = batch(&[("nulls", "1.0.0"), ("blank", "1.0.0"), ("plain", "1.0.0")]);
        let body = [
            r#"{"inputPurl":"pkg:npm/nulls@1.0.0","type":null,"name":null,"version":null,"alerts":[]}"#,
            r#"{"type":"npm","name":"blank","version":"1.0.0","alerts":[{"type":"  "}]}"#,
            r#"{"type":"npm","namespace":null,"name":"plain","version":"1.0.0","alerts":[]}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [Verdict::Unknown, Verdict::Unknown, Verdict::Clean]
        );
    }

    #[test]
    fn a_token_that_cant_be_sent_in_a_header_is_a_failure_found_on_this_machine() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::update([
            ("LPM_HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ("SOCKET_CLI_API_TOKEN", Some("token\nwith a newline".into())),
            ("SOCKET_SECURITY_API_TOKEN", None),
            (API_OVERRIDE_VARIABLE, None),
        ]);

        let failure = Endpoint::resolve().err().unwrap();

        assert!(failure.local, "{failure:?}");
    }

    #[test]
    fn alert_types_padded_with_whitespace_still_decide_the_verdict() {
        let packages = batch(&[("flagged", "1.0.0"), ("new", "1.0.0")]);
        let body = [
            r#"{"type":"npm","name":"flagged","version":"1.0.0","alerts":[{"type":"malware "}]}"#,
            r#"{"type":"npm","name":"new","version":"1.0.0","alerts":[{"type":" pendingScan"}]}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [malware("malware"), Verdict::Pending]
        );
    }

    #[test]
    fn a_pending_scan_outranks_a_malformed_alert() {
        let packages = batch(&[("new", "1.0.0")]);
        let body = r#"{"type":"npm","name":"new","version":"1.0.0","alerts":[{"type":null},{"type":"pendingScan"}]}"#;

        assert_eq!(parse_answer(body.as_bytes(), &packages), [Verdict::Pending]);
    }

    #[test]
    fn purl_errors_are_pending_when_retryable_and_unknown_otherwise() {
        let packages = batch(&[("slow", "1.0.0"), ("gone", "1.0.0")]);
        let body = [
            r#"{"_type":"purlError","value":{"error":"timeout","inputPurl":"pkg:npm/slow@1.0.0","retryable":true}}"#,
            r#"{"_type":"purlError","value":{"error":"not found","inputPurl":"pkg:npm/gone@1.0.0"}}"#,
        ]
        .join("\n");

        assert_eq!(
            parse_answer(body.as_bytes(), &packages),
            [Verdict::Pending, Verdict::Unknown]
        );
    }

    #[test]
    fn login_refuses_to_check_a_token_with_an_override_and_each_endpoint_keeps_its_own_cache() {
        let _env = crate::test_env::ScopedEnv::set([(
            API_OVERRIDE_VARIABLE,
            "https://socket.example/v0".into(),
        )]);
        assert!(endpoint_for_login("token", false).is_err());
        assert!(endpoint_for_login("token", true).is_ok());
        let override_scope = cache_scope().unwrap();
        drop(_env);
        assert_eq!(cache_scope().as_deref(), Some("socket"));
        assert_ne!(override_scope, "socket");
    }

    #[tokio::test]
    async fn a_round_whose_deadline_already_passed_asks_nothing() {
        let server = socket_with_batches(&[200, 200]).await;
        let endpoint = Endpoint {
            base: format!("{}/v0", server.uri()),
            token: SecretString::from("token".to_string()),
        };
        let packages = batch(&[("bad", "1.0.0"), ("later", "1.0.0")]);

        let answers = lookup_in_batches(&endpoint, &packages, 1, tokio::time::Instant::now())
            .await
            .unwrap();

        assert!(answers.verdicts.is_empty());
        assert!(answers.failure.unwrap().reason.contains("didn't answer"));
    }

    #[test]
    fn organization_slugs_are_plain_url_segments() {
        assert!(is_organization_slug("acme"));
        assert!(is_organization_slug("acme-inc_2.0"));
        assert!(!is_organization_slug(""));
        assert!(!is_organization_slug(".."));
        assert!(!is_organization_slug("acme/../other"));
        assert!(!is_organization_slug("acme?x=1"));
    }

    #[test]
    fn an_unusable_api_override_is_refused_rather_than_ignored() {
        for url in [
            "http://socket.example/v0",
            "https://socket.example/v0?token=x",
            "https://socket.example/v0#fragment",
            "https://user:secret@socket.example/v0",
        ] {
            let _env = crate::test_env::ScopedEnv::set([(API_OVERRIDE_VARIABLE, url.into())]);
            assert!(api_override().is_err(), "{url}");
        }
        let _env = crate::test_env::ScopedEnv::set([(
            API_OVERRIDE_VARIABLE,
            "https://socket.example/v0/".into(),
        )]);
        assert_eq!(
            api_override(),
            Ok(Some("https://socket.example/v0".to_string()))
        );
    }

    async fn socket_with_batches(statuses: &[u16]) -> wiremock::MockServer {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/organizations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "organizations": { "1": { "slug": "acme" } }
            })))
            .mount(&server)
            .await;
        for status in statuses {
            let body =
                r#"{"type":"npm","name":"bad","version":"1.0.0","alerts":[{"type":"malware"}]}"#;
            Mock::given(method("POST"))
                .and(path("/v0/orgs/acme/purl"))
                .respond_with(ResponseTemplate::new(*status).set_body_string(body))
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }
        server
    }

    #[tokio::test]
    async fn a_failed_batch_keeps_the_verdicts_earlier_batches_gave() {
        let server = socket_with_batches(&[200, 503]).await;
        let endpoint = Endpoint {
            base: format!("{}/v0", server.uri()),
            token: SecretString::from("token".to_string()),
        };
        let packages = batch(&[("bad", "1.0.0"), ("later", "1.0.0")]);

        let answers = lookup_in_batches(&endpoint, &packages, 1, deadline())
            .await
            .unwrap();

        assert_eq!(
            answers
                .verdicts
                .get(&("bad".to_string(), "1.0.0".to_string()))
                .map(|observed| &observed.verdict),
            Some(&malware("malware"))
        );
        assert!(
            !answers
                .verdicts
                .contains_key(&("later".to_string(), "1.0.0".to_string()))
        );
        assert!(answers.failure.unwrap().reason.contains("503"));
    }

    #[tokio::test]
    async fn a_deadline_reached_mid_round_keeps_the_batches_answered_before_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = socket_with_batches(&[200]).await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/purl"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let endpoint = Endpoint {
            base: format!("{}/v0", server.uri()),
            token: SecretString::from("token".to_string()),
        };
        let packages = batch(&[("bad", "1.0.0"), ("later", "1.0.0")]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);

        let answers = lookup_in_batches(&endpoint, &packages, 1, deadline)
            .await
            .unwrap();

        assert!(
            answers
                .verdicts
                .contains_key(&("bad".to_string(), "1.0.0".to_string()))
        );
        assert!(
            !answers
                .verdicts
                .contains_key(&("later".to_string(), "1.0.0".to_string()))
        );
        assert!(answers.failure.is_some());
        assert!(tokio::time::Instant::now() < deadline + Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_redirect_is_never_followed_with_the_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/organizations"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "/elsewhere/organizations"),
            )
            .mount(&server)
            .await;
        let endpoint = Endpoint {
            base: format!("{}/v0", server.uri()),
            token: SecretString::from("token".to_string()),
        };

        let failure = organization(&client().unwrap(), &endpoint, deadline())
            .await
            .unwrap_err();

        assert!(failure.reason.contains("307"), "{failure:?}");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
    }
}
