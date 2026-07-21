//! Shared construction and error handling for LPM's outbound HTTP clients.

use std::error::Error as _;
use std::fmt;

use reqwest::redirect::Policy;

/// Reqwest's default maximum number of automatically followed redirects.
pub const DEFAULT_REDIRECT_LIMIT: usize = 10;

/// Stable user-facing error for a redirect that would weaken transport security.
pub const HTTPS_DOWNGRADE_REFUSAL: &str = "refused HTTPS-to-HTTP redirect";

#[derive(Debug)]
struct HttpsDowngrade;

impl fmt::Display for HttpsDowngrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(HTTPS_DOWNGRADE_REFUSAL)
    }
}

impl std::error::Error for HttpsDowngrade {}

/// Build an asynchronous reqwest client with the workspace redirect policy.
pub fn client_builder() -> reqwest::ClientBuilder {
    client_builder_with_redirect_limit(DEFAULT_REDIRECT_LIMIT)
}

/// Build an asynchronous reqwest client with a caller-selected redirect limit.
pub fn client_builder_with_redirect_limit(limit: usize) -> reqwest::ClientBuilder {
    reqwest::Client::builder().redirect(redirect_policy(limit))
}

/// Build a blocking reqwest client with the workspace redirect policy.
pub fn blocking_client_builder() -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder().redirect(redirect_policy(DEFAULT_REDIRECT_LIMIT))
}

/// Build a bounded redirect policy that refuses cleartext after any HTTPS hop.
pub fn redirect_policy(limit: usize) -> Policy {
    let bounded = Policy::limited(limit);
    Policy::custom(move |attempt| {
        let target_is_http = attempt.url().scheme() == "http";
        let chain_used_https = attempt.previous().iter().any(|url| url.scheme() == "https");
        if target_is_http && chain_used_https {
            attempt.error(HttpsDowngrade)
        } else {
            bounded.redirect(attempt)
        }
    })
}

/// Return whether a reqwest failure was caused by the HTTPS downgrade policy.
pub fn is_https_downgrade(error: &reqwest::Error) -> bool {
    let mut source = error.source();
    while let Some(current) = source {
        if current.downcast_ref::<HttpsDowngrade>().is_some() {
            return true;
        }
        source = current.source();
    }
    false
}

fn refusal_message(error: &reqwest::Error) -> Option<&'static str> {
    let mut source = error.source();
    while let Some(current) = source {
        if current.downcast_ref::<HttpsDowngrade>().is_some() {
            return Some(HTTPS_DOWNGRADE_REFUSAL);
        }
        source = current.source();
    }
    None
}

/// Display a request error without exposing URLs from a downgrade refusal.
pub fn display_error(error: &reqwest::Error) -> ErrorDisplay<'_> {
    ErrorDisplay { error }
}

/// A redacting display adapter for outbound HTTP errors.
pub struct ErrorDisplay<'a> {
    error: &'a reqwest::Error,
}

impl fmt::Display for ErrorDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(message) = refusal_message(self.error) {
            formatter.write_str(message)
        } else {
            self.error.fmt(formatter)
        }
    }
}

/// Render a full error chain while redacting downgrade-refusal URLs.
pub fn error_chain(error: &reqwest::Error) -> String {
    if let Some(message) = refusal_message(error) {
        return message.to_string();
    }

    let mut messages = Vec::with_capacity(4);
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(current) = source {
        messages.push(current.to_string());
        source = current.source();
    }
    messages.join(" <- ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_redirect_limit_matches_reqwest_default() {
        assert_eq!(DEFAULT_REDIRECT_LIMIT, 10);
    }
}
