use std::collections::HashSet;

use lpm_common::LpmError;
use lpm_semver::Version;

use super::discovery::DiscoveredPackage;
use super::policy::{min_severity_level, severity_level};

/// Outcome of an OSV scan.
///
/// `degraded_reason` is `Some(_)` when the OSV API returned a non-2xx
/// status, refused the connection, or otherwise failed — semantics
/// previously conflated with "scan completed successfully and found
/// nothing." A green audit run that the user could not previously
/// distinguish from a degraded one is a transient OSV
/// outage (or an attacker who can sink the OSV connection) silently
/// hid every CVE.
pub(super) struct OsvScanOutcome {
    pub(super) vulns: Vec<OsvVulnerability>,
    pub(super) degraded_reason: Option<String>,
}

/// Query OSV for all non-@lpm.dev packages, deduplicating by (name, version).
pub(super) async fn run_osv_scan(
    packages: &[DiscoveredPackage],
    _json_output: bool,
    level: Option<&str>,
) -> OsvScanOutcome {
    // Collect non-@lpm.dev packages eligible for OSV
    let mut osv_queries: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for pkg in packages {
        // Skip @lpm.dev packages — they get vuln data from registry metadata
        if pkg.name.starts_with("@lpm.dev/") {
            continue;
        }

        // We intentionally do NOT skip packages based on resolved URL.
        // Even packages resolved from a corporate proxy (Verdaccio, Artifactory,
        // or the LPM registry worker) are typically mirrors of public npm packages.
        // Skipping them based on URL silently removes OSV coverage. OSV returns
        // empty for unknown packages, so there's no false-positive risk for
        // querying a public name that was resolved from a proxy.

        let key = (pkg.name.clone(), pkg.version.clone());
        if seen.insert(key.clone()) {
            osv_queries.push(key);
        }
    }

    if osv_queries.is_empty() {
        return OsvScanOutcome {
            vulns: Vec::new(),
            degraded_reason: None,
        };
    }

    let vulns = match query_osv_batch(&osv_queries).await {
        Ok(v) => v,
        Err(e) => {
            let reason = e.to_string();
            // Promote to `warn` (was `debug`) so a degraded audit
            // never hides in default tracing output. The human renderer
            // prints the warning once; the JSON envelope carries the
            // structured `osv_degraded` field for machine consumption.
            tracing::warn!("OSV query failed: {reason}");
            return OsvScanOutcome {
                vulns: Vec::new(),
                degraded_reason: Some(reason),
            };
        }
    };

    let filtered = if let Some(lvl) = level {
        let min_lvl = min_severity_level(lvl);
        vulns
            .into_iter()
            .filter(|v| severity_level(&v.severity) >= min_lvl)
            .collect()
    } else {
        vulns
    };
    OsvScanOutcome {
        vulns: filtered,
        degraded_reason: None,
    }
}

// ─── OSV.dev integration ────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    pub(super) vulns: Vec<OsvVuln>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvVuln {
    pub(super) id: String,
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffected {
    pub(super) package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvAffectedRange>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedPackage {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedRange {
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvAffectedEvent>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedEvent {
    fixed: Option<String>,
}

#[derive(Debug)]
pub(super) struct OsvVulnerability {
    pub(super) package: String,
    pub(super) version: String,
    pub(super) id: String,
    pub(super) summary: String,
    pub(super) severity: String,
    pub(super) fixed_versions: Vec<String>,
}

const OSV_URL_DEFAULT: &str = "https://api.osv.dev/v1/querybatch";

/// Resolve the OSV endpoint, honouring `LPM_OSV_URL` overrides only
/// when the scheme/host combination matches the same gating contract as
/// the self-update release probe (`release_lookup::resolve_release_url`):
/// HTTPS is always accepted; plain HTTP is accepted only when the host
/// is a loopback address so workflow tests can target a localhost mock
/// without opening a generic env-poisoning hole. Honoured and rejected
/// overrides both emit `warn` so operator logs surface unexpected
/// redirects of the advisory feed.
fn resolve_osv_url() -> String {
    let raw = match std::env::var("LPM_OSV_URL").ok().filter(|s| !s.is_empty()) {
        Some(v) => v,
        None => return OSV_URL_DEFAULT.to_string(),
    };
    if osv_override_is_accepted(&raw) {
        tracing::warn!(
            override_url = %raw,
            "LPM_OSV_URL override honoured — confirm this is expected",
        );
        return raw;
    }
    tracing::warn!(
        override_url = %raw,
        "rejecting LPM_OSV_URL override: plain HTTP non-loopback URL or unsupported scheme; \
         falling back to default — set the override to an https:// URL to use a private mirror",
    );
    OSV_URL_DEFAULT.to_string()
}

/// Accept an override URL if it's HTTPS (any host) or HTTP pointed at
/// a loopback address. Mirrors `release_lookup::accept_override` so the
/// two env-driven advisory/version endpoints share an identical
/// abuse-window posture.
pub(super) fn osv_override_is_accepted(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match parsed.scheme() {
        "https" => true,
        "http" => parsed.host_str().is_some_and(host_is_loopback),
        _ => false,
    }
}

fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(addr) = inner.parse::<std::net::IpAddr>()
    {
        return addr.is_loopback();
    }
    false
}

/// Query OSV.dev for known vulnerabilities.
///
/// # Trust Model
/// OSV responses are fetched over HTTPS, which prevents passive eavesdropping
/// and basic MITM attacks. However, there is no certificate pinning or response
/// signing. A sophisticated attacker with access to a trusted CA (e.g., corporate
/// MITM proxy) could inject false "no vulnerabilities" responses.
///
/// This matches the security posture of npm audit, yarn audit, and other tools
/// that query advisory databases over HTTPS without additional verification.
///
/// Uses the batch endpoint to minimize HTTP round-trips (single request for all packages).
/// Gracefully returns an empty vec on any network/parse failure.
pub(super) async fn query_osv_batch(
    packages: &[(String, String)],
) -> Result<Vec<OsvVulnerability>, LpmError> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    let client = reqwest::Client::new();

    let queries: Vec<serde_json::Value> = packages
        .iter()
        .map(|(name, version)| {
            serde_json::json!({
                "package": { "name": name, "ecosystem": "npm" },
                "version": version,
            })
        })
        .collect();

    let body = serde_json::json!({ "queries": queries });

    let osv_url = resolve_osv_url();

    let response = client
        .post(&osv_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OSV API error: {e}")))?;

    if !response.status().is_success() {
        // Surface the failure as an error rather than silently
        // returning an empty result. The pre-fix `Ok(Vec::new())`
        // was indistinguishable from "no vulnerabilities found" —
        // an attacker who could downstream block / fail the OSV
        // endpoint (env override, transient outage, MITM-stripped
        // TLS) could make `lpm audit` falsely report a green
        // result. The caller renders a "degraded mode" warning
        // and exits with a distinct semantic so CI gates do not
        // confuse "unreachable advisory DB" with "clean scan".
        return Err(LpmError::Network(format!(
            "OSV API returned HTTP {}; treat as degraded — vulnerability data not retrieved",
            response.status().as_u16()
        )));
    }

    let result: OsvBatchResponse = response
        .json()
        .await
        .map_err(|e| LpmError::Network(format!("OSV parse error: {e}")))?;

    let mut vulns: Vec<OsvVulnerability> = Vec::new();

    for (i, query_result) in result.results.into_iter().enumerate() {
        if i >= packages.len() {
            break;
        }
        for vuln in query_result.vulns {
            let fixed_versions = osv_fixed_versions_for_package(&vuln, &packages[i].0);
            vulns.push(OsvVulnerability {
                package: packages[i].0.clone(),
                version: packages[i].1.clone(),
                id: vuln.id,
                summary: vuln.summary.unwrap_or_default(),
                severity: extract_severity(&vuln.severity),
                fixed_versions,
            });
        }
    }

    Ok(vulns)
}

fn osv_fixed_versions_for_package(vuln: &OsvVuln, package_name: &str) -> Vec<String> {
    let mut fixed = Vec::new();
    for affected in &vuln.affected {
        if let Some(package) = &affected.package {
            if package
                .ecosystem
                .as_deref()
                .is_some_and(|ecosystem| !ecosystem.eq_ignore_ascii_case("npm"))
            {
                continue;
            }
            if package
                .name
                .as_deref()
                .is_some_and(|name| name != package_name)
            {
                continue;
            }
        }
        for range in &affected.ranges {
            if range
                .range_type
                .as_deref()
                .is_some_and(|kind| !kind.eq_ignore_ascii_case("semver"))
            {
                continue;
            }
            for event in &range.events {
                if let Some(version) = event.fixed.as_deref()
                    && Version::parse(version).is_ok()
                {
                    fixed.push(version.to_string());
                }
            }
        }
    }
    fixed.sort();
    fixed.dedup();
    fixed
}

/// Extract the highest severity string from OSV severity entries.
fn extract_severity(entries: &[OsvSeverityEntry]) -> String {
    for entry in entries {
        if entry.severity_type == "CVSS_V3" {
            return cvss_score_to_label(&entry.score);
        }
    }
    if let Some(entry) = entries.first() {
        return cvss_score_to_label(&entry.score);
    }
    "UNKNOWN".to_string()
}

/// Convert a CVSS vector string to a severity label.
pub(super) fn cvss_score_to_label(score_str: &str) -> String {
    if let Ok(score) = score_str.parse::<f64>() {
        return if score >= 9.0 {
            "CRITICAL".to_string()
        } else if score >= 7.0 {
            "HIGH".to_string()
        } else if score >= 4.0 {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        };
    }
    if score_str.contains("CVSS:") {
        "HIGH".to_string()
    } else {
        "UNKNOWN".to_string()
    }
}
