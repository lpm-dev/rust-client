use super::*;

#[test]
fn validate_base_url_rejects_http_non_localhost() {
    let client = RegistryClient::new().with_base_url("http://evil.com");
    let result = client.validate_base_url();
    assert!(result.is_err(), "HTTP non-localhost should be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("insecure"),
        "error should mention insecure: {msg}"
    );
}

#[test]
fn validate_base_url_allows_http_localhost() {
    let client = RegistryClient::new().with_base_url("http://localhost:3000");
    assert!(
        client.validate_base_url().is_ok(),
        "HTTP localhost should be allowed"
    );
}

#[test]
fn validate_base_url_allows_http_127() {
    let client = RegistryClient::new().with_base_url("http://127.0.0.1:3000");
    assert!(
        client.validate_base_url().is_ok(),
        "HTTP 127.0.0.1 should be allowed"
    );
}

#[test]
fn validate_base_url_allows_http_ipv6_loopback() {
    let client = RegistryClient::new().with_base_url("http://[::1]:3000");
    assert!(
        client.validate_base_url().is_ok(),
        "HTTP [::1] should be allowed"
    );
}

#[test]
fn validate_base_url_rejects_localhost_prefix_attack_domain() {
    let client = RegistryClient::new().with_base_url("http://localhost.evil.com:3000");
    let result = client.validate_base_url();
    assert!(
        result.is_err(),
        "attacker-controlled localhost prefix domain should be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("insecure"),
        "error should mention insecure transport: {msg}"
    );
}

#[test]
fn validate_base_url_allows_https() {
    let client = RegistryClient::new().with_base_url("https://lpm.dev");
    assert!(
        client.validate_base_url().is_ok(),
        "HTTPS should always be allowed"
    );
}

#[test]
fn validate_base_url_allows_insecure_override() {
    let client = RegistryClient::new()
        .with_base_url("http://evil.com")
        .with_insecure(true);
    assert!(
        client.validate_base_url().is_ok(),
        "HTTP non-localhost with --insecure should be allowed"
    );
}

#[test]
fn validate_base_url_rejects_file_scheme_even_with_insecure() {
    // `--insecure` is narrow: it widens to HTTP only, never to
    // `file://`. A `file://` base URL with the flag set must still
    // be rejected — otherwise a misconfigured tool could read
    // arbitrary local paths as if they were a registry.
    let client = RegistryClient::new()
        .with_base_url("file:///etc/passwd")
        .with_insecure(true);
    let result = client.validate_base_url();
    assert!(
        result.is_err(),
        "file:// must be rejected even with --insecure"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("insecure"),
        "error should mention insecure transport: {msg}"
    );
}

#[test]
fn validate_base_url_rejects_non_http_schemes_even_with_insecure() {
    // Parity with the tarball-path gate: only HTTPS, localhost HTTP,
    // and (with --insecure) HTTP everywhere are valid. `ftp://`,
    // `data:`, `javascript:` etc. stay rejected regardless.
    for url in [
        "ftp://mirror.example.com/",
        "data:text/plain,hello",
        "javascript:alert(1)",
    ] {
        let client = RegistryClient::new().with_base_url(url).with_insecure(true);
        assert!(
            client.validate_base_url().is_err(),
            "{url} must be rejected even with --insecure"
        );
    }
}

#[test]
fn check_tarball_url_scheme_allows_https() {
    let client = RegistryClient::new();
    assert!(
        client
            .check_tarball_url_scheme("https://lpm.dev/pkg/-/pkg-1.0.0.tgz")
            .is_ok()
    );
}

#[test]
fn check_tarball_url_scheme_allows_localhost_http() {
    let client = RegistryClient::new();
    for url in [
        "http://localhost:3000/pkg/-/pkg-1.0.0.tgz",
        "http://127.0.0.1:3000/pkg/-/pkg-1.0.0.tgz",
        "http://[::1]:3000/pkg/-/pkg-1.0.0.tgz",
    ] {
        assert!(
            client.check_tarball_url_scheme(url).is_ok(),
            "loopback HTTP should always be allowed: {url}"
        );
    }
}

#[test]
fn check_tarball_url_scheme_rejects_http_non_localhost_without_insecure() {
    let client = RegistryClient::new();
    let result = client.check_tarball_url_scheme("http://evil.com/pkg.tgz");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("tarball URL must use HTTPS"),
        "error should name the requirement: {msg}"
    );
    assert!(
        msg.contains("--insecure"),
        "error should hint at --insecure flag: {msg}"
    );
}

#[test]
fn check_tarball_url_scheme_allows_http_non_localhost_with_insecure() {
    // Directly exercises the new `--insecure` carve-out without
    // making a real HTTP request. The flag opts into HTTP
    // explicitly, so the guard must accept it.
    let client = RegistryClient::new().with_insecure(true);
    assert!(
        client
            .check_tarball_url_scheme("http://mirror.example/pkg/-/pkg-1.0.0.tgz")
            .is_ok()
    );
}

#[test]
fn check_tarball_url_scheme_rejects_file_even_with_insecure() {
    // `--insecure` is HTTP-only by contract (see `--insecure` help text in
    // lpm-cli and the doc comment on `check_tarball_url_scheme`). `file://`
    // must remain rejected even with the flag set, or a tampered lockfile
    // could steer the installer at arbitrary local files.
    let client = RegistryClient::new().with_insecure(true);
    let result = client.check_tarball_url_scheme("file:///etc/passwd");
    assert!(
        result.is_err(),
        "file:// must be rejected even with --insecure"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("tarball URL must use HTTPS"),
        "error should name the requirement: {msg}"
    );
}

#[test]
fn check_tarball_url_scheme_rejects_non_http_schemes_even_with_insecure() {
    // Same contract guard as the file:// case, extended to the
    // other non-HTTP schemes an attacker-controlled lockfile or
    // metadata response could try to sneak through.
    let client = RegistryClient::new().with_insecure(true);
    for url in [
        "ftp://mirror.example.com/pkg.tgz",
        "data:application/octet-stream,AAAA",
        "javascript:fetch('/admin')",
        "gopher://evil.com/pkg.tgz",
    ] {
        assert!(
            client.check_tarball_url_scheme(url).is_err(),
            "{url} must be rejected even with --insecure"
        );
    }
}

#[test]
fn is_http_url_cases() {
    assert!(is_http_url("http://evil.com/pkg.tgz"));
    assert!(is_http_url("http://localhost:3000/pkg.tgz"));
    assert!(!is_http_url("https://lpm.dev/pkg.tgz"));
    assert!(!is_http_url("file:///etc/passwd"));
    assert!(!is_http_url("ftp://mirror.example/pkg.tgz"));
    assert!(!is_http_url("not a url"));
}

#[test]
fn is_localhost_url_cases() {
    assert!(is_localhost_url("http://localhost:3000"));
    assert!(is_localhost_url("http://localhost"));
    assert!(is_localhost_url("http://127.0.0.1:3000"));
    assert!(is_localhost_url("http://[::1]:3000"));
    assert!(!is_localhost_url("http://localhost.evil.com:3000"));
    assert!(!is_localhost_url("http://127.0.0.1.evil.com:3000"));
    assert!(!is_localhost_url("http://[::1].evil.com:3000"));
    assert!(!is_localhost_url("http://evil.com"));
    assert!(!is_localhost_url("https://lpm.dev"));
}

#[test]
fn is_localhost_url_recognises_ipv4_mapped_ipv6_loopback() {
    assert!(
        is_localhost_url("http://[::ffff:127.0.0.1]:3000"),
        "IPv4-mapped IPv6 loopback must be recognised",
    );
    assert!(
        is_localhost_url("http://[::ffff:127.1.2.3]:3000"),
        "any IPv4-mapped address in 127.0.0.0/8 is loopback",
    );
    // And the negative: a mapped non-loopback v4 is NOT loopback.
    assert!(
        !is_localhost_url("http://[::ffff:8.8.8.8]:3000"),
        "mapped public IPv4 must not be treated as loopback",
    );
}

#[test]
fn is_localhost_url_accepts_full_127_block() {
    assert!(is_localhost_url("http://127.42.42.42:3000"));
    assert!(is_localhost_url("http://127.255.255.254:3000"));
}

#[test]
fn gate_accepts_canonical_lpm_tarball_url() {
    let client = RegistryClient::new().with_base_url("https://lpm.dev");
    // Canonical LPM tarball path: /api/registry/{scope}/{pkg}/-/...tgz
    let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
    assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
}

#[test]
fn gate_accepts_canonical_npm_tarball_url() {
    let client = RegistryClient::new();
    // Default `npm_registry_url` is `https://registry.npmjs.org`.
    let url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
    assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
}

#[test]
fn gate_rejects_non_https_non_localhost_without_insecure() {
    let client = RegistryClient::new().with_base_url("https://lpm.dev");
    // HTTP (non-localhost) — scheme check fires first.
    let url = "http://evil.com/pkg/-/pkg-1.0.0.tgz";
    assert_eq!(
        evaluate_cached_url(url, &client),
        GateDecision::RejectedScheme
    );
}

#[test]
fn gate_accepts_http_with_insecure() {
    // `--insecure` widens the scheme carve-out so lockfile-cached
    // HTTP tarball URLs can be reused when the user explicitly
    // opted into insecure transport. Shape + origin gates still
    // fire — here the base URL is the mirror's HTTP origin so
    // `is_configured_origin` returns true.
    let client = RegistryClient::new()
        .with_base_url("http://mirror.internal")
        .with_insecure(true);
    let url = "http://mirror.internal/pkg/-/pkg-1.0.0.tgz";
    assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
}

#[test]
fn gate_rejects_file_scheme_even_with_insecure() {
    // `--insecure` is HTTP-only by contract, never `file://`. A tampered
    // lockfile that stashed a `file:///etc/passwd` URL must be rejected
    // regardless of the flag state, before the bearer token is attached.
    let client = RegistryClient::new()
        .with_base_url("https://lpm.dev")
        .with_insecure(true);
    assert_eq!(
        evaluate_cached_url("file:///etc/passwd", &client),
        GateDecision::RejectedScheme
    );
}

#[test]
fn gate_rejects_wrong_suffix() {
    let client = RegistryClient::new().with_base_url("https://lpm.dev");
    // HTTPS + correct origin + `/-/` segment — but not `.tgz`.
    let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.zip";
    assert_eq!(
        evaluate_cached_url(url, &client),
        GateDecision::RejectedShape
    );
}

#[test]
fn gate_rejects_admin_style_path_without_dash_segment() {
    // H1 auth-token leak defense: `.tgz` suffix alone isn't enough
    // — the `/-/` segment requirement is what rules out attacker-
    // crafted `/api/admin/foo.tgz` paths.
    let client = RegistryClient::new().with_base_url("https://lpm.dev");
    let url = "https://lpm.dev/api/admin/foo.tgz";
    assert_eq!(
        evaluate_cached_url(url, &client),
        GateDecision::RejectedShape
    );
}

#[test]
fn gate_rejects_origin_mismatch_after_registry_switch() {
    // User switches `LPM_REGISTRY_URL` to a mirror. Stored
    // `@lpm.dev/*` URLs now mismatch the configured origin and
    // fall through to on-demand lookup.
    let client = RegistryClient::new().with_base_url("http://localhost:9999");
    let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
    assert_eq!(
        evaluate_cached_url(url, &client),
        GateDecision::RejectedOrigin
    );
}

#[test]
fn gate_allows_localhost_registry() {
    // Dev workflow — HTTP to localhost is explicitly permitted
    // (same carve-out `download_tarball_to_file` has pre-flight).
    let client = RegistryClient::new().with_base_url("http://localhost:3000");
    let url = "http://localhost:3000/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
    assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
}

#[test]
fn gate_rejects_malformed_url() {
    let client = RegistryClient::new();
    assert_eq!(
        evaluate_cached_url("not a url", &client),
        GateDecision::RejectedScheme,
    );
}

#[test]
fn rejected_registry_and_tarball_urls_redact_credentials_paths_and_queries() {
    let registry_secret = "registry-password";
    let registry = RegistryClient::new().with_base_url(format!(
        "http://user:{registry_secret}@registry.example/private?token=query-secret"
    ));
    let registry_error = registry.validate_base_url().unwrap_err().to_string();
    for secret in [registry_secret, "private", "query-secret"] {
        assert!(
            !registry_error.contains(secret),
            "registry error leaked {secret}: {registry_error}"
        );
    }

    let tarball_secret = "tarball-password";
    let tarball_url = format!(
        "ftp://user:{tarball_secret}@registry.example/private/package.tgz?token=tarball-query"
    );
    let tarball_error = RegistryClient::new()
        .check_tarball_url_scheme(&tarball_url)
        .unwrap_err()
        .to_string();
    for secret in [tarball_secret, "private", "tarball-query"] {
        assert!(
            !tarball_error.contains(secret),
            "tarball error leaked {secret}: {tarball_error}"
        );
    }
}

#[test]
fn rejected_long_unicode_tarball_url_returns_an_error_without_panicking() {
    let url = format!("ftp://registry.example/{}é/package.tgz", "a".repeat(56));
    let result = std::panic::catch_unwind(|| RegistryClient::new().check_tarball_url_scheme(&url));
    assert!(
        result.is_ok(),
        "malformed Unicode URL must not panic error formatting"
    );
    assert!(result.unwrap().is_err());
}
