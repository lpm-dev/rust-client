use std::collections::{HashMap, HashSet};

use futures::{StreamExt, stream};
use lpm_common::LpmError;
use lpm_semver::Version;

use super::discovery::DiscoveredPackage;
use super::policy::{AuditLevel, min_severity_level, severity_level};

/// Outcome of an OSV scan.
///
/// `degraded_reason` is `Some(_)` when the advisory scan did not complete.
pub(super) struct OsvScanOutcome {
    pub(super) vulns: Vec<OsvVulnerability>,
    pub(super) degraded_reason: Option<String>,
}

/// Query OSV for all non-@lpm.dev packages, deduplicating by (name, version).
pub(super) async fn run_osv_scan(
    packages: &[DiscoveredPackage],
    json_output: bool,
    level: Option<AuditLevel>,
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

    let vulns = match query_osv_batch_with_warnings(&osv_queries, !json_output).await {
        Ok(v) => v,
        Err(e) => {
            let reason = e.to_string();
            // Promote to `warn` (was `debug`) so a degraded audit
            // never hides in default tracing output. The human renderer
            // prints the warning once; the JSON envelope carries the
            // structured `osv_degraded` field for machine consumption.
            if !json_output {
                tracing::warn!("OSV query failed: {reason}");
            }
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

#[derive(Debug, Clone, serde::Deserialize)]
struct OsvVuln {
    pub(super) id: String,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: OsvDatabaseSpecific,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct OsvDatabaseSpecific {
    severity: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    _severity_type: String,
    score: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OsvAffected {
    pub(super) package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvAffectedRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OsvAffectedPackage {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OsvAffectedRange {
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvAffectedEvent>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OsvAffectedEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct OsvVulnerability {
    pub(super) package: String,
    pub(super) version: String,
    pub(super) id: String,
    pub(super) summary: String,
    pub(super) severity: String,
    affected: Vec<OsvAffected>,
}

impl OsvVulnerability {
    pub(super) fn affects_version(&self, version: &str) -> Result<bool, String> {
        evaluate_affected_ranges(&self.affected, &self.package, version)?.ok_or_else(|| {
            format!(
                "OSV advisory {} does not publish evaluable npm affected ranges",
                self.id
            )
        })
    }
}

const OSV_URL_DEFAULT: &str = "https://api.osv.dev/v1/querybatch";

/// Resolve the OSV endpoint, honouring `LPM_OSV_URL` overrides only
/// when the scheme/host combination matches the same gating contract as
/// the self-update release probe (`release_lookup::resolve_release_url`):
/// HTTPS is always accepted; plain HTTP is accepted only when the host
/// is a loopback address so workflow tests can target a localhost mock
/// overrides both emit `warn` so operator logs surface unexpected
/// redirects of the advisory feed.
fn resolve_osv_url(emit_warnings: bool) -> String {
    let raw = match std::env::var("LPM_OSV_URL").ok().filter(|s| !s.is_empty()) {
        Some(v) => v,
        None => return OSV_URL_DEFAULT.to_string(),
    };
    if osv_override_is_accepted(&raw) {
        if emit_warnings {
            tracing::warn!(
                override_url = %raw,
                "LPM_OSV_URL override honoured — confirm this is expected",
            );
        }
        return raw;
    }
    if emit_warnings {
        tracing::warn!(
            override_url = %raw,
            "rejecting LPM_OSV_URL override: plain HTTP non-loopback URL or unsupported scheme; \
             falling back to default — set the override to an https:// URL to use a private mirror",
        );
    }
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
/// Uses the batch endpoint for package queries, then hydrates sparse advisory matches.
/// Network, parsing, hydration, and incomplete-response failures are returned to the caller.
#[cfg(test)]
pub(super) async fn query_osv_batch(
    packages: &[(String, String)],
) -> Result<Vec<OsvVulnerability>, LpmError> {
    query_osv_batch_with_warnings(packages, true).await
}

async fn query_osv_batch_with_warnings(
    packages: &[(String, String)],
    emit_warnings: bool,
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

    let osv_url = resolve_osv_url(emit_warnings);

    let response = client
        .post(&osv_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OSV API error: {e}")))?;

    if !response.status().is_success() {
        return Err(LpmError::Network(format!(
            "OSV API returned HTTP {}; treat as degraded — vulnerability data not retrieved",
            response.status().as_u16()
        )));
    }

    let result: OsvBatchResponse = response
        .json()
        .await
        .map_err(|e| LpmError::Network(format!("OSV parse error: {e}")))?;

    if result.results.len() != packages.len() {
        return Err(LpmError::Network(format!(
            "OSV batch response cardinality mismatch: sent {} queries, received {} result slots",
            packages.len(),
            result.results.len()
        )));
    }

    let mut hydration_ids = HashSet::new();
    for query_result in &result.results {
        for vuln in &query_result.vulns {
            if osv_advisory_needs_hydration(vuln) {
                hydration_ids.insert(vuln.id.clone());
            }
        }
    }

    let hydrated: Vec<(String, OsvVuln)> = stream::iter(hydration_ids.into_iter().map(|id| {
        let client = client.clone();
        let osv_url = osv_url.clone();
        async move {
            let vuln = fetch_osv_advisory(&client, &osv_url, &id).await?;
            Ok::<_, LpmError>((id, vuln))
        }
    }))
    .buffer_unordered(8)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let hydrated: HashMap<String, OsvVuln> = hydrated.into_iter().collect();

    let mut vulns: Vec<OsvVulnerability> = Vec::new();

    for (query_result, (package, version)) in result.results.into_iter().zip(packages) {
        for batch_vuln in query_result.vulns {
            let vuln = hydrated.get(&batch_vuln.id).unwrap_or(&batch_vuln);
            if matches!(
                evaluate_affected_ranges(&vuln.affected, package, version),
                Ok(Some(false))
            ) {
                continue;
            }
            vulns.push(OsvVulnerability {
                package: package.clone(),
                version: version.clone(),
                id: vuln.id.clone(),
                summary: vuln.summary.clone().unwrap_or_default(),
                severity: extract_severity(vuln),
                affected: vuln.affected.clone(),
            });
        }
    }

    Ok(vulns)
}

fn osv_advisory_needs_hydration(vuln: &OsvVuln) -> bool {
    vuln.summary.is_none()
        || vuln.affected.is_empty()
        || (vuln.severity.is_empty() && vuln.database_specific.severity.is_none())
}

async fn fetch_osv_advisory(
    client: &reqwest::Client,
    batch_url: &str,
    id: &str,
) -> Result<OsvVuln, LpmError> {
    let mut url = reqwest::Url::parse(batch_url)
        .map_err(|e| LpmError::Network(format!("invalid OSV API URL: {e}")))?;
    url.set_path(&format!("/v1/vulns/{}", urlencoding::encode(id)));
    url.set_query(None);
    let response = client
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OSV advisory hydration failed for {id}: {e}")))?;
    if !response.status().is_success() {
        return Err(LpmError::Network(format!(
            "OSV advisory hydration for {id} returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let vuln: OsvVuln = response
        .json()
        .await
        .map_err(|e| LpmError::Network(format!("OSV advisory parse failed for {id}: {e}")))?;
    if vuln.id != id {
        return Err(LpmError::Network(format!(
            "OSV advisory hydration identity mismatch: requested {id}, received {}",
            vuln.id
        )));
    }
    Ok(vuln)
}

fn evaluate_affected_ranges(
    affected_entries: &[OsvAffected],
    package_name: &str,
    version: &str,
) -> Result<Option<bool>, String> {
    let candidate = Version::parse(version)
        .map_err(|error| format!("cannot evaluate non-semver version '{version}': {error}"))?;
    let mut evaluated = false;
    let mut evaluation_error = None;

    for affected in affected_entries {
        let Some(package) = &affected.package else {
            evaluation_error = Some("OSV affected entry is missing package identity".to_string());
            continue;
        };
        let Some(ecosystem) = package.ecosystem.as_deref() else {
            evaluation_error = Some("OSV affected package is missing its ecosystem".to_string());
            continue;
        };
        if !ecosystem.eq_ignore_ascii_case("npm") {
            continue;
        }
        let Some(affected_name) = package.name.as_deref() else {
            evaluation_error = Some("OSV affected npm package is missing its name".to_string());
            continue;
        };
        if affected_name != package_name {
            continue;
        }

        if !affected.versions.is_empty() {
            evaluated = true;
            if affected.versions.iter().any(|item| item == version) {
                return Ok(Some(true));
            }
        }

        for range in &affected.ranges {
            let Some(range_type) = range.range_type.as_deref() else {
                evaluation_error = Some("OSV affected range is missing its type".to_string());
                continue;
            };
            if !range_type.eq_ignore_ascii_case("semver") {
                evaluation_error = Some(format!(
                    "unsupported OSV affected range type '{range_type}'"
                ));
                continue;
            }
            if range.events.is_empty() {
                evaluation_error = Some("OSV semver range has no events".to_string());
                continue;
            }
            evaluated = true;
            if osv_range_affects_version(range, &candidate)? {
                return Ok(Some(true));
            }
        }
    }

    if let Some(reason) = evaluation_error {
        Err(reason)
    } else if evaluated {
        Ok(Some(false))
    } else {
        Ok(None)
    }
}

fn osv_range_affects_version(
    range: &OsvAffectedRange,
    candidate: &Version,
) -> Result<bool, String> {
    let mut interval_open = false;
    let mut candidate_in_interval = false;
    for event in &range.events {
        let field_count = [
            event.introduced.is_some(),
            event.fixed.is_some(),
            event.last_affected.is_some(),
            event.limit.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if field_count != 1 {
            return Err("OSV semver event must contain exactly one boundary".to_string());
        }

        if let Some(introduced) = event.introduced.as_deref() {
            if interval_open {
                return Err(
                    "OSV semver range introduced a new interval before closing the previous one"
                        .to_string(),
                );
            }
            interval_open = true;
            candidate_in_interval =
                introduced == "0" || candidate >= &parse_osv_event_version(introduced)?;
            continue;
        }

        if !interval_open {
            return Err("OSV semver range closed an interval before introducing it".to_string());
        }
        if let Some(fixed) = event.fixed.as_deref() {
            candidate_in_interval &= candidate < &parse_osv_event_version(fixed)?;
        } else if let Some(last_affected) = event.last_affected.as_deref() {
            candidate_in_interval &= candidate <= &parse_osv_event_version(last_affected)?;
        } else if let Some(limit) = event.limit.as_deref() {
            candidate_in_interval &= candidate < &parse_osv_event_version(limit)?;
        }
        if candidate_in_interval {
            return Ok(true);
        }
        interval_open = false;
    }
    Ok(interval_open && candidate_in_interval)
}

fn parse_osv_event_version(version: &str) -> Result<Version, String> {
    Version::parse(version)
        .map_err(|error| format!("invalid semver '{version}' in OSV affected range: {error}"))
}

/// Extract the highest severity string from OSV severity entries.
fn extract_severity(vuln: &OsvVuln) -> String {
    let mut labels: Vec<String> = vuln
        .severity
        .iter()
        .map(|entry| cvss_score_to_label(&entry.score))
        .filter(|label| label != "UNKNOWN")
        .collect();
    if let Some(severity) = vuln.database_specific.severity.as_deref() {
        let label = match severity.to_ascii_lowercase().as_str() {
            "critical" => "CRITICAL",
            "high" => "HIGH",
            "moderate" => "MODERATE",
            "medium" => "MEDIUM",
            "low" => "LOW",
            _ => "UNKNOWN",
        };
        if label != "UNKNOWN" {
            labels.push(label.to_string());
        }
    }
    labels
        .into_iter()
        .max_by_key(|label| severity_level(label))
        .unwrap_or_else(|| "UNKNOWN".to_string())
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
    if score_str.starts_with("CVSS:3.")
        && ["/AV:", "/AC:", "/PR:", "/UI:", "/S:", "/C:", "/I:", "/A:"]
            .iter()
            .any(|metric| !score_str.contains(metric))
    {
        return "UNKNOWN".to_string();
    }
    score_str
        .parse::<cvss::Cvss>()
        .map(|vector| match vector.severity() {
            cvss::Severity::Critical => "CRITICAL",
            cvss::Severity::High => "HIGH",
            cvss::Severity::Medium => "MEDIUM",
            cvss::Severity::Low | cvss::Severity::None => "LOW",
        })
        .unwrap_or("UNKNOWN")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_events_mark_versions_before_fixed_as_affected() {
        let vulnerability: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "vuln-pkg"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
            }]
        }))
        .unwrap();
        assert_eq!(
            evaluate_affected_ranges(&vulnerability.affected, "vuln-pkg", "1.0.0"),
            Ok(Some(true))
        );
        assert_eq!(
            evaluate_affected_ranges(&vulnerability.affected, "vuln-pkg", "1.0.1"),
            Ok(Some(false))
        );
    }

    #[test]
    fn database_specific_moderate_severity_is_preserved() {
        let vulnerability: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test",
            "database_specific": {"severity": "MODERATE"}
        }))
        .unwrap();
        assert_eq!(extract_severity(&vulnerability), "MODERATE");
    }

    #[test]
    fn semver_range_without_introduced_event_is_not_treated_as_safe() {
        let vulnerability: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "GHSA-malformed",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "vuln-pkg"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.0.1"}]}]
            }]
        }))
        .unwrap();

        assert!(evaluate_affected_ranges(&vulnerability.affected, "vuln-pkg", "1.0.1").is_err());
    }

    #[test]
    fn affected_entry_without_package_identity_is_not_evaluable() {
        let vulnerability: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "GHSA-unattributed",
            "affected": [{
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "1.0.1"}
                ]}]
            }]
        }))
        .unwrap();

        assert!(evaluate_affected_ranges(&vulnerability.affected, "vuln-pkg", "1.0.1").is_err());
    }

    #[test]
    fn advisory_without_affected_data_requires_hydration() {
        let vulnerability: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "GHSA-partial",
            "summary": "partial advisory",
            "severity": [{"type": "CVSS_V3", "score": "8.0"}]
        }))
        .unwrap();

        assert!(osv_advisory_needs_hydration(&vulnerability));
    }
}
