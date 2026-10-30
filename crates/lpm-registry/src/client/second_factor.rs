//! A request's second factor: how the registry asks for it, and what LPM CLI
//! sends back.

use lpm_common::LpmError;

/// Says the CLI can wait for a browser approval, so the registry asks for
/// one instead of refusing an account that can only confirm there.
pub(super) const BROWSER_APPROVAL_SUPPORT_HEADER: &str = "x-lpm-browser-approval";

/// What a request that needs the account's second factor carries.
#[derive(Clone, Copy, Debug)]
pub enum SecondFactorProof<'a> {
    /// A six-digit code from the account's authenticator app.
    Code(&'a str),
    /// The one-time token of the browser approval of this request.
    Approval(&'a str),
}

impl<'a> SecondFactorProof<'a> {
    /// The header that carries it, and its value.
    pub(super) fn header(self) -> (&'static str, &'a str) {
        match self {
            Self::Code(code) => ("x-otp", code),
            Self::Approval(token) => ("x-lpm-approval", token),
        }
    }
}

/// The error a 401 from a request that may need the second factor is: the
/// registry asking for a browser approval of `action`, a code it asked for
/// or refused, an approval it refused, or else a sign-in to refresh, as
/// `LpmError::AuthRequired`.
///
/// A refused approval is final: refreshing the session and sending its
/// token again would only be refused again.
pub(super) fn second_factor_unauthorized_error(
    body: &serde_json::Value,
    command: &'static str,
    action: &str,
) -> LpmError {
    let text = |field: &str| body.get(field).and_then(serde_json::Value::as_str);
    let flag = |field: &str| body.get(field).and_then(serde_json::Value::as_bool) == Some(true);
    if let (Some(auth_url), Some(done_url)) = (text("authUrl"), text("doneUrl")) {
        return LpmError::BrowserApprovalRequired {
            action: action.to_owned(),
            auth_url: auth_url.to_owned(),
            done_url: done_url.to_owned(),
            accepts_code: flag("otp"),
            has_passkey: flag("passkey"),
        };
    }
    match text("code") {
        Some("OTP_REQUIRED") => LpmError::OtpRequired { command },
        Some("OTP_INVALID") => LpmError::OtpInvalid { command },
        Some("APPROVAL_INVALID") => LpmError::Registry(
            text("error")
                .unwrap_or("the browser approval is invalid, expired, or already used")
                .to_owned(),
        ),
        _ => LpmError::AuthRequired,
    }
}
