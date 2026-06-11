use super::*;

/// Check if a URL points to a localhost address.
///
/// Used by `evaluate_cached_url` and tarball download guards to compose
/// URL-safety checks.
pub fn is_localhost_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };

    if parsed.scheme() != "http" {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let normalized_host = host.trim_start_matches('[').trim_end_matches(']');
    normalized_host
        .parse::<std::net::IpAddr>()
        .is_ok_and(is_loopback_ip)
}

/// Loopback check that handles both native loopback (`127.0.0.0/8`,
/// `::1`) and the IPv4-mapped IPv6 shape (`::ffff:127.0.0.1`).
/// Rust's `IpAddr::is_loopback` only flags the native forms, so an
/// `http://[::ffff:127.0.0.1]/foo` URL would otherwise sneak past
/// the localhost gate and through HTTPS-required code paths.
pub(super) fn is_loopback_ip(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Check if a URL uses the HTTPS scheme.
pub fn is_https_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "https")
}

/// Pre-validate a PEM root before handing it to
/// `reqwest::Certificate::from_pem`. Reqwest's rustls-tls `from_pem` is
/// permissive (stores raw bytes; cryptographic validation happens at
/// `.build()` time), and a `.build()` failure can't tell us WHICH root
/// caused it. This function fails fast on the common shape mistakes —
/// non-UTF-8 bytes, missing markers, empty or non-base64 body — and
/// cites the contributing source/line so the user can find the
/// offending `.npmrc` line.
///
/// **Multi-block bundles:** every `BEGIN..END` pair in the buffer is
/// validated. Common shape: a corporate cafile with `[root, intermediate]`
/// concatenated. If block 2 is malformed, we fail at validation rather
/// than letting the build-time error swallow the source context.
///
/// Returning `Ok(())` does NOT guarantee the certs are cryptographically
/// valid (that's still a `.build()`-time concern). It only guarantees
/// "every block is shaped like a PEM cert with a non-empty base64 body."
///
/// Pairs with [`contains_pem_certificate_block`] in `npmrc.rs`, which
/// performs the cheaper "any BEGIN marker present" parser-time check at
/// config-load.
pub(super) fn validate_pem_root(
    pem_bytes: &[u8],
    source: &str,
    line: usize,
) -> Result<(), LpmError> {
    use base64::Engine as _;
    let text = std::str::from_utf8(pem_bytes).map_err(|e| {
        LpmError::Cert(format!(
            "npmrc cafile/ca at {source}:{line}: PEM is not valid UTF-8: {e}"
        ))
    })?;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if !text.contains(BEGIN) {
        return Err(LpmError::Cert(format!(
            "npmrc cafile/ca at {source}:{line}: no '{BEGIN}' marker"
        )));
    }
    let mut cursor = text;
    let mut block_no: usize = 0;
    while let Some(begin_off) = cursor.find(BEGIN) {
        block_no += 1;
        let after_begin = &cursor[begin_off + BEGIN.len()..];
        let end_off = after_begin.find(END).ok_or_else(|| {
            LpmError::Cert(format!(
                "npmrc cafile/ca at {source}:{line} block #{block_no}: no '{END}' marker"
            ))
        })?;
        let body: String = after_begin[..end_off]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if body.is_empty() {
            return Err(LpmError::Cert(format!(
                "npmrc cafile/ca at {source}:{line} block #{block_no}: empty certificate body"
            )));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .map_err(|e| {
                LpmError::Cert(format!(
                    "npmrc cafile/ca at {source}:{line} block #{block_no}: certificate body is not valid base64: {e}"
                ))
            })?;
        if decoded.is_empty() {
            return Err(LpmError::Cert(format!(
                "npmrc cafile/ca at {source}:{line} block #{block_no}: certificate body decodes to zero bytes"
            )));
        }
        cursor = &after_begin[end_off + END.len()..];
    }
    Ok(())
}

/// Check if a URL uses the HTTP scheme.
///
/// Paired with [`is_https_url`] and [`is_localhost_url`] so the
/// `--insecure` carve-out can specifically widen the scheme gate
/// to plain HTTP — not to `file://`, `ftp://`, `data:`, or any
/// other non-HTTPS scheme. See
/// [`RegistryClient::check_tarball_url_scheme`] for the enforcement site.
pub fn is_http_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "http")
}

/// Outcome of [`evaluate_cached_url`] — gate on lockfile-stored tarball
/// URLs before they're dispatched to the fetch pipeline. A dedicated
/// variant per rejection reason so callers can emit targeted telemetry
/// (`tarball_url_origin_mismatch_count` vs `_shape_mismatch_count`)
/// without re-running the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// URL passes scheme + shape + origin; safe to reuse.
    Accepted,
    /// Neither HTTPS nor `http://localhost`. The writer should
    /// never emit a scheme-rejected URL, so a non-zero counter
    /// here signals a corrupt lockfile.
    RejectedScheme,
    /// Path doesn't match a canonical tarball shape (`/-/` segment
    /// AND `.tgz` suffix). Blocks the H1 auth-token leak: a
    /// tampered lockfile pointing at `/api/admin/foo.tgz` would
    /// otherwise attach the bearer to a non-registry endpoint.
    /// Non-zero counter = BUG signal — investigate the writer.
    RejectedShape,
    /// URL's origin is not in the set this client is configured
    /// to talk to (`{base_url, npm_registry_url}`). Expected to
    /// be non-zero after `LPM_REGISTRY_URL` switches: stored
    /// `@lpm.dev/*` URLs mismatch the new origin → fall through
    /// to on-demand lookup against the mirror.
    RejectedOrigin,
}

/// Gate a lockfile-stored tarball URL before reusing it on the fetch
/// path. Combines scheme, shape, and origin checks with a distinct
/// `GateDecision` per rejection reason so callers can bump the right
/// telemetry counter.
///
/// The shape check requires both `.tgz` suffix AND a `/-/` path segment.
/// Both LPM (`/api/registry/{scope}/{pkg}/-/...`) and npm (`/{pkg}/-/...`)
/// emit URLs in this shape; attacker-crafted `.tgz`-suffixed admin paths
/// like `/api/admin/foo.tgz` lack the `/-/` segment and are rejected
/// before the bearer is attached.
pub fn evaluate_cached_url(url: &str, client: &RegistryClient) -> GateDecision {
    // Scheme — mirrors `RegistryClient::check_tarball_url_scheme` so
    // the lockfile-read gate stays symmetric with the tarball-download
    // guards. `--insecure` specifically widens the carve-out to HTTP,
    // never to `file://`, `ftp://`, `data:`, etc.
    let scheme_ok =
        is_https_url(url) || is_localhost_url(url) || (client.allow_insecure() && is_http_url(url));
    if !scheme_ok {
        return GateDecision::RejectedScheme;
    }

    // Shape — `/-/` segment AND `.tgz` suffix. Suffix-only checks can
    // be bypassed with administrative-looking paths like
    // `/api/admin/foo.tgz`; the `/-/` segment is only ever emitted by
    // the registry tarball route.
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return GateDecision::RejectedShape;
    };
    let path = parsed.path();
    if !path.ends_with(".tgz") || !path.contains("/-/") {
        return GateDecision::RejectedShape;
    }

    // Origin — must match one of the origins this client talks to.
    // After `LPM_REGISTRY_URL` is switched to a mirror, stored
    // `@lpm.dev/*` URLs naturally mismatch and fall through to
    // on-demand lookup against the new origin. The writeback trigger
    // picks up the fresh URLs and rewrites the lockfile so the second
    // install short-circuits.
    if !client.is_configured_origin(url) {
        return GateDecision::RejectedOrigin;
    }

    GateDecision::Accepted
}
