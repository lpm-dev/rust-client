//! A registry's refusal of a request, as the registry described it.

use std::fmt;

/// Which registry answered, which decides the advice a refusal gets: only
/// lpm.dev knows `lpm login`, and npm's own registry has no `.npmrc` scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryKind {
    /// lpm.dev, or the LPM registry this CLI is configured for.
    Lpm,
    /// registry.npmjs.org.
    Npm,
    /// Any other registry, such as one a `.npmrc` scope names.
    Custom,
}

impl RegistryKind {
    /// The name `--json` gives this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lpm => "lpm",
            Self::Npm => "npm",
            Self::Custom => "custom",
        }
    }
}

/// What the body of an error answer was, for the fallback message when the
/// registry sent none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryBodyKind {
    Json,
    Html,
    /// An XML error, as object storage (S3, R2, GCS) answers.
    Xml,
    Text,
    Empty,
}

/// A registry's non-success answer: its status, the registry, and what it
/// said, already sanitized for a terminal row and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryHttpError {
    pub status: u16,
    /// The registry's origin, such as `https://lpm.dev`, with no path or
    /// credentials.
    pub registry: String,
    pub registry_kind: RegistryKind,
    /// The registry's machine-readable code, such as `PACKAGE_NOT_FOUND`.
    pub code: Option<String>,
    /// The registry's message, or a description of its answer when it sent
    /// none.
    pub message: String,
    /// Whether `message` is the registry's own words.
    pub message_from_registry: bool,
    pub body_kind: RegistryBodyKind,
    /// An id the registry's support can find the request by.
    pub request_id: Option<String>,
    /// The seconds `Retry-After` asked to wait, as the registry said them.
    pub retry_after_secs: Option<u64>,
    /// An `npm-notice` header the registry sent with the answer.
    pub notice: Option<String>,
    /// The package or `package@version` the request was for, when the
    /// caller knows it.
    pub subject: Option<String>,
}

impl RegistryHttpError {
    /// The registry's host, for messages.
    pub fn registry_host(&self) -> &str {
        self.registry
            .split_once("://")
            .map_or(self.registry.as_str(), |(_, rest)| rest)
            .trim_end_matches('/')
    }

    /// The registry's status and its reason phrase, such as `403 Forbidden`.
    pub fn status_line(&self) -> String {
        let phrase = match self.status {
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            413 => "Content Too Large",
            415 => "Unsupported Media Type",
            422 => "Unprocessable Content",
            423 => "Locked",
            429 => "Too Many Requests",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "",
        };
        if phrase.is_empty() {
            self.status.to_string()
        } else {
            format!("{} {phrase}", self.status)
        }
    }

    /// What the user can do about the refusal, beyond what the registry
    /// said: advice that depends on which registry answered, since only
    /// lpm.dev knows `lpm login` and only `.npmrc` configures the others.
    /// None when the registry's own message already says what to do.
    pub fn hint(&self) -> Option<String> {
        let host = self.registry_host();
        let npmrc_token = format!("//{host}/:_authToken");
        match (self.status, self.registry_kind) {
            (401, RegistryKind::Lpm) if self.code.is_some() && self.message_from_registry => None,
            (401, RegistryKind::Lpm) => {
                Some("Run `lpm login`, or set LPM_TOKEN to a valid token.".into())
            }
            (401, RegistryKind::Npm) => Some(format!(
                "Check the npm token in .npmrc ({npmrc_token}), or run `npm login`."
            )),
            (401, RegistryKind::Custom) => Some(format!(
                "Check the token for {host} in .npmrc ({npmrc_token})."
            )),
            (403, RegistryKind::Lpm) if self.message_from_registry => None,
            (403, RegistryKind::Lpm) => {
                Some("Check that your lpm.dev account or token can read this package.".into())
            }
            (403, _) => Some(format!(
                "Check that the token for {host} in .npmrc ({npmrc_token}) can read this package."
            )),
            (404, RegistryKind::Lpm) => Some(
                "Check the package name and version. `lpm search <query>` lists lpm.dev packages."
                    .into(),
            ),
            (404, RegistryKind::Npm) => Some(
                "Check the package name and version. Packages outside @lpm.dev come from registry.npmjs.org unless .npmrc names another registry for their scope."
                    .into(),
            ),
            (404, RegistryKind::Custom) => Some(format!(
                "Check the package name and version, and that .npmrc should send its scope to {host}."
            )),
            (408 | 500..=599, _) => Some(match &self.request_id {
                Some(id) => format!(
                    "{host} failed to answer. Retry in a moment; if it keeps failing, give its support request id {id}."
                ),
                None => format!("{host} failed to answer. Retry in a moment."),
            }),
            _ if self.message_from_registry => None,
            _ => Some(format!(
                "{host} gave no reason. Retry, or check the registry's status."
            )),
        }
    }

    /// The same refusal, naming what it was for.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

/// The message a registry's error body gives in the fields registries use
/// (`error`, `message`, `detail` (RFC 7807), `reason`), sanitized to one
/// bounded terminal row, for callers that read an answer outside the
/// registry client.
pub fn registry_error_body_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    ["error", "message", "detail", "reason"]
        .into_iter()
        .find_map(|field| value.get(field)?.as_str())
        .map(|text| crate::sanitize_server_text(text, 600))
        .filter(|text| !text.is_empty())
}

/// The refusal on one line, as `--json`'s `error` and nested reports carry
/// it: what it was for, which registry answered with which status, and
/// what the registry said. A message the registry didn't send already
/// names the registry and status.
impl fmt::Display for RegistryHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(subject) = self
            .subject
            .as_deref()
            .filter(|subject| !self.message.contains(subject))
        {
            write!(f, "{subject}: ")?;
        }
        if self.message_from_registry {
            write!(
                f,
                "{} answered {}: {}",
                self.registry_host(),
                self.status_line(),
                self.message
            )?;
        } else {
            f.write_str(&self.message)?;
        }
        match self.retry_after_secs {
            Some(wait) if matches!(self.status, 429 | 503) => {
                write!(f, " (retry after {wait}s)")
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, kind: RegistryKind, from_registry: bool) -> RegistryHttpError {
        RegistryHttpError {
            status,
            registry: match kind {
                RegistryKind::Lpm => "https://lpm.dev".into(),
                RegistryKind::Npm => "https://registry.npmjs.org".into(),
                RegistryKind::Custom => "https://npm.example.com".into(),
            },
            registry_kind: kind,
            code: None,
            message: "m".into(),
            message_from_registry: from_registry,
            body_kind: RegistryBodyKind::Json,
            request_id: None,
            retry_after_secs: None,
            notice: None,
            subject: None,
        }
    }

    #[test]
    fn advises_lpm_login_only_for_lpm() {
        assert!(
            answer(401, RegistryKind::Lpm, true)
                .hint()
                .unwrap()
                .contains("lpm login")
        );
        let custom = answer(401, RegistryKind::Custom, true).hint().unwrap();
        assert!(!custom.contains("lpm login"));
        assert!(custom.contains("//npm.example.com/:_authToken"));
        assert!(
            answer(401, RegistryKind::Npm, true)
                .hint()
                .unwrap()
                .contains("npm login")
        );
    }

    #[test]
    fn suggests_lpm_search_only_for_lpm_packages() {
        assert!(
            answer(404, RegistryKind::Lpm, true)
                .hint()
                .unwrap()
                .contains("lpm search")
        );
        assert!(
            !answer(404, RegistryKind::Npm, true)
                .hint()
                .unwrap()
                .contains("lpm search")
        );
    }

    #[test]
    fn leaves_an_lpm_refusal_that_says_what_to_do_to_speak_for_itself() {
        assert_eq!(answer(403, RegistryKind::Lpm, true).hint(), None);
        assert_eq!(answer(409, RegistryKind::Custom, true).hint(), None);
        assert!(answer(409, RegistryKind::Custom, false).hint().is_some());
    }

    #[test]
    fn names_the_request_id_when_a_registry_fails() {
        let mut failed = answer(503, RegistryKind::Lpm, true);
        failed.request_id = Some("req_abc".into());
        assert!(failed.hint().unwrap().contains("req_abc"));
        assert_eq!(failed.status_line(), "503 Service Unavailable");
    }
}
