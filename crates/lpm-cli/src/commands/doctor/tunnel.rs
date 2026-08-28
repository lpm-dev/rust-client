#[cfg(test)]
use std::path::Path;
use std::time::Duration;

use crate::doctor_catalog;
use lpm_registry::RegistryClient;

use super::check::{Check, FixTarget};

const TUNNEL_DIAGNOSTIC_DEADLINE: Duration = Duration::from_secs(5);

/// Check tunnel domain configuration from lpm.json.
///
/// Performs format validation (RFC 1035/1123 compliance, subdomain constraints,
/// known base domain whitelist), ownership check (via registry API when authenticated),
/// and HTTP reachability check for claimed domains.
pub(super) async fn check_tunnel_domain_from_config(
    config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    client: &RegistryClient,
    is_authenticated: bool,
) -> Vec<Check> {
    let Some(config) = config else {
        return Vec::new();
    };
    let tunnel = match &config.tunnel {
        Some(t) => t,
        None => return vec![],
    };
    let domain = match &tunnel.domain {
        Some(d) => d,
        None => return vec![],
    };

    let mut checks = Vec::new();

    // RFC-compliant domain length checks (RFC 1035 / RFC 1123)
    if domain.len() > 253 {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_DOMAIN_TOO_LONG,
            &format!(
                "domain \"{}\" exceeds 253 character limit ({} chars)",
                domain,
                domain.len()
            ),
        ));
        return checks;
    }

    // Check each label: max 63 chars, no empty labels (consecutive dots)
    for label in domain.split('.') {
        if label.is_empty() {
            checks.push(Check::warn(
                &doctor_catalog::TUNNEL_DOMAIN_EMPTY_LABEL,
                &format!("domain \"{domain}\" contains empty label (consecutive dots)"),
            ));
            return checks;
        }
        if label.len() > 63 {
            checks.push(Check::warn(
                &doctor_catalog::TUNNEL_DOMAIN_LABEL_TOO_LONG,
                &format!(
                    "domain label \"{}\" exceeds 63 character limit ({} chars)",
                    label,
                    label.len()
                ),
            ));
            return checks;
        }
    }

    // Validate domain format: must have at least one dot
    if !domain.contains('.') {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_DOMAIN_NO_DOT,
            &format!(
                "\"{}\" is not a full domain — use: {}.lpm.fyi or {}.lpm.llc",
                domain, domain, domain
            ),
        ));
        return checks;
    }

    // Split into subdomain + base domain (guaranteed to have a dot from check above)
    let parts: Vec<&str> = domain.splitn(2, '.').collect();
    let subdomain = parts[0];
    let base_domain = parts[1];

    // Check subdomain format
    if subdomain.len() < 3 || subdomain.len() > 32 {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_SUBDOMAIN_LENGTH,
            &format!("subdomain \"{subdomain}\" must be 3-32 characters"),
        ));
        return checks;
    }
    if !subdomain
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_SUBDOMAIN_CHARS,
            &format!("subdomain \"{subdomain}\" must be lowercase alphanumeric + hyphens"),
        ));
        return checks;
    }
    if subdomain.starts_with('-') || subdomain.ends_with('-') {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_SUBDOMAIN_HYPHEN,
            &format!("subdomain \"{subdomain}\" must not start or end with a hyphen"),
        ));
        return checks;
    }

    // Check known base domains — only deployed domains
    let known_bases = ["lpm.fyi", "lpm.llc"];
    if !known_bases.contains(&base_domain) {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_UNKNOWN_BASE,
            &format!(
                "unknown base domain \"{base_domain}\" (available: {})",
                known_bases.join(", ")
            ),
        ));
        return checks;
    }

    // === Ownership check (requires auth) ===
    if !is_authenticated {
        checks.push(Check::pass(
            &doctor_catalog::TUNNEL_UNAUTHENTICATED,
            &format!("{domain} (configured, login to verify ownership)"),
        ));
        return checks;
    }

    // Check if domain is claimed by this user via registry API
    let check = tokio::time::timeout(
        TUNNEL_DIAGNOSTIC_DEADLINE,
        check_authenticated_tunnel(client, domain),
    )
    .await
    .unwrap_or_else(|_| {
        Check::warn(
            &doctor_catalog::TUNNEL_UNVERIFIED,
            &format!("{domain} (configured, ownership check exceeded the diagnostic deadline)"),
        )
    });
    checks.push(check);

    checks
}

async fn check_authenticated_tunnel(client: &RegistryClient, domain: &str) -> Check {
    let result = match client.diagnostic_tunnel_domain_lookup_once(domain).await {
        Ok(result) => result,
        Err(_) => {
            return Check::warn(
                &doctor_catalog::TUNNEL_UNVERIFIED,
                &format!("{domain} (configured, could not verify ownership)"),
            );
        }
    };
    if !result["found"].as_bool().unwrap_or(false) {
        return Check::warn_with_fix_target(
            &doctor_catalog::TUNNEL_NOT_CLAIMED,
            &format!("{domain} — not claimed. Run: lpm tunnel claim {domain}"),
            FixTarget::TunnelDomain(domain.to_owned()),
        );
    }
    if !result["ownedByYou"].as_bool().unwrap_or(false) {
        return Check::warn(
            &doctor_catalog::TUNNEL_OWNED_BY_OTHER,
            &format!("{domain} — claimed by another user or org"),
        );
    }
    match check_tunnel_reachability(domain).await {
        TunnelReachability::Active => Check::pass(
            &doctor_catalog::TUNNEL_ACTIVE,
            &format!("{domain} (claimed, active)"),
        ),
        TunnelReachability::Idle => Check::pass(
            &doctor_catalog::TUNNEL_IDLE,
            &format!("{domain} (claimed, idle)"),
        ),
        TunnelReachability::Unreachable => Check::warn(
            &doctor_catalog::TUNNEL_UNREACHABLE,
            &format!("{domain} (claimed) — unreachable, DNS may not be configured"),
        ),
    }
}

#[cfg(test)]
async fn check_tunnel_domain(
    project_dir: &Path,
    client: &RegistryClient,
    is_authenticated: bool,
) -> Vec<Check> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    check_tunnel_domain_from_config(config.as_ref(), client, is_authenticated).await
}

enum TunnelReachability {
    Active,
    Idle,
    Unreachable,
}

/// Quick HTTP HEAD check to see if a tunnel domain is reachable.
async fn check_tunnel_reachability(domain: &str) -> TunnelReachability {
    let url = format!("https://{domain}");
    let client = match lpm_http::client_builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return TunnelReachability::Unreachable,
    };

    match client.head(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 404 {
                // Worker returns 404 when tunnel is not active
                TunnelReachability::Idle
            } else {
                TunnelReachability::Active
            }
        }
        Err(_) => TunnelReachability::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;
    use lpm_registry::RegistryClient;

    // ── Tunnel domain checks (format validation, no auth) ──────────

    #[tokio::test]
    async fn tunnel_check_skipped_without_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert!(checks.is_empty(), "no tunnel check when no lpm.json");
    }

    #[tokio::test]
    async fn tunnel_check_skipped_without_tunnel_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "runtime": { "node": "22" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert!(checks.is_empty(), "no tunnel check when no tunnel section");
    }

    #[tokio::test]
    async fn tunnel_check_warns_bare_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not a full domain"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_unknown_base_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme.lpm.run" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0].detail.contains("unknown base domain"),
            "should reject unannounced lpm.run: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn tunnel_check_passes_valid_domain_unauthenticated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme-api.lpm.llc" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("configured"));
        assert!(checks[0].detail.contains("login to verify"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_short_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "ab.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("3-32 characters"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_uppercase_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "ACME.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("lowercase"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_leading_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "-acme.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0]
                .detail
                .contains("must not start or end with a hyphen"),
            "should reject leading hyphen: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn tunnel_check_warns_trailing_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme-.lpm.llc" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0]
                .detail
                .contains("must not start or end with a hyphen"),
            "should reject trailing hyphen: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn authenticated_tunnel_lookup_obeys_the_diagnostic_deadline() {
        use std::time::Instant;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tunnel/domains/doctor-deadline.lpm.fyi"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "found": true,
                        "ownedByYou": true,
                    }))
                    .set_delay(Duration::from_secs(6)),
            )
            .mount(&server)
            .await;
        let client = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("doctor-token");
        let config = lpm_runner::lpm_json::parse_lpm_json(
            r#"{"tunnel":{"domain":"doctor-deadline.lpm.fyi"}}"#,
        )
        .unwrap();
        let started = Instant::now();

        let checks = check_tunnel_domain_from_config(Some(&config), &client, true).await;

        assert!(
            started.elapsed() < Duration::from_millis(5_750),
            "tunnel lookup exceeded the five-second diagnostic bound: {:?}",
            started.elapsed()
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].code(), "tunnel_unverified");
        assert!(matches!(checks[0].severity, Severity::Warn));
    }
}
