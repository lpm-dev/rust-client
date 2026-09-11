use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, HeaderMap, PROXY_AUTHORIZATION};

pub(super) async fn read_request_error_text(
    response: reqwest::Response,
    request: &reqwest::Request,
) -> String {
    let mut text = super::read_capped_error_text(response).await;
    redact_credentials(&mut text, request.headers());
    text
}

fn redact_credentials(text: &mut String, headers: &HeaderMap) {
    for name in [AUTHORIZATION, PROXY_AUTHORIZATION] {
        let Some(header) = headers.get(name).and_then(|value| value.to_str().ok()) else {
            continue;
        };
        let Some((scheme, credential)) = header.split_once(' ') else {
            redact_secret(text, header);
            continue;
        };
        redact_secret(text, credential);
        if scheme.eq_ignore_ascii_case("basic")
            && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credential)
            && let Ok(decoded) = std::str::from_utf8(&decoded)
        {
            redact_secret(text, decoded);
            if let Some((_, password)) = decoded.split_once(':') {
                redact_secret(text, password);
            }
        }
    }
    for name in ["npm-otp", "x-otp"] {
        if let Some(secret) = headers.get(name).and_then(|value| value.to_str().ok()) {
            redact_secret(text, secret);
        }
    }
}

fn redact_secret(text: &mut String, secret: &str) {
    if let std::borrow::Cow::Owned(redacted) = lpm_common::redact_exact_secret(text, secret) {
        *text = redacted;
    }
    if secret
        .bytes()
        .any(|byte| byte == b'"' || byte == b'\\' || byte < 0x20)
        && let Ok(encoded) = serde_json::to_string(secret)
        && let std::borrow::Cow::Owned(redacted) =
            lpm_common::redact_exact_secret(text, &encoded[1..encoded.len() - 1])
    {
        *text = redacted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_json_escaped_bearer_and_basic_password() {
        let secret = r#"password\with"quotes"#;
        for authorization in [
            format!("Bearer {secret}"),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("user:{secret}"))
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, authorization.parse().unwrap());
            let mut text = serde_json::json!({"error": format!("denied {secret}")}).to_string();
            redact_credentials(&mut text, &headers);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["error"], "denied <redacted>");
        }
    }

    #[test]
    fn redacts_proxy_and_otp_values_without_dropping_error_context() {
        let mut headers = HeaderMap::new();
        headers.insert(PROXY_AUTHORIZATION, "Bearer proxy-secret".parse().unwrap());
        headers.insert("npm-otp", "654321".parse().unwrap());
        let mut text = "denied proxy-secret with code 654321".to_owned();
        redact_credentials(&mut text, &headers);
        assert_eq!(text, "denied <redacted> with code <redacted>");
    }

    #[test]
    fn absent_credentials_do_not_change_an_error() {
        let mut text = "permission denied".to_owned();
        redact_credentials(&mut text, &HeaderMap::new());
        assert_eq!(text, "permission denied");
    }
}
