use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallBatchPackage {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallBatchResponse {
    pub request_id: String,
    pub policy_mode: String,
    pub summary: NpmFirewallSummary,
    #[serde(default)]
    pub diagnostics: Option<NpmFirewallDiagnostics>,
    pub decisions: Vec<NpmFirewallDecision>,
    #[serde(skip)]
    pub client_timing: Option<NpmFirewallClientTiming>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallClientTiming {
    pub request_ms: u64,
    pub body_read_ms: u64,
    pub json_parse_ms: u64,
    pub total_ms: u64,
    pub request_body_bytes: u64,
    pub response_body_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NpmFirewallDiagnostics {
    pub package_count: u64,
    pub lookup_concurrency: u64,
    pub kv_read_count: u64,
    pub kv_lookup_ms: f64,
    pub entitlement_ms: f64,
    pub parse_ms: f64,
    pub total_ms: f64,
    pub matched_count: u64,
    pub decision_detail: Option<String>,
    pub returned_decision_count: u64,
    pub kv_namespace_label: Option<String>,
    pub flagged_package_index: Option<NpmFirewallFlaggedPackageIndexDiagnostics>,
    pub match_sources: NpmFirewallMatchSources,
    pub lookup_duration: NpmFirewallLookupDuration,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NpmFirewallFlaggedPackageIndexDiagnostics {
    pub enabled: bool,
    pub used: bool,
    pub status: Option<String>,
    pub cache_status: Option<String>,
    pub key: Option<String>,
    pub read_ms: f64,
    pub package_key_count: u64,
    pub candidate_count: u64,
    pub detail_read_count: u64,
    pub skipped_package_lookup_count: u64,
    pub generated_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct NpmFirewallMatchSources {
    pub integrity: u64,
    pub package: u64,
    pub none: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NpmFirewallLookupDuration {
    pub count: u64,
    pub sum_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
pub struct NpmFirewallSummary {
    pub total: u64,
    pub allow: u64,
    pub warn: u64,
    pub block: u64,
    pub unknown: u64,
    pub matched: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallDecision {
    pub decision_id: String,
    pub name: String,
    pub version: String,
    pub action: NpmFirewallAction,
    pub verdict: String,
    pub reason: String,
    pub match_source: String,
    pub matched_key: Option<String>,
    pub policy_mode: String,
    #[serde(default)]
    pub enqueue_scan: bool,
    pub scanned_at: Option<serde_json::Value>,
    pub scan_run_id: Option<String>,
    pub report_path: Option<String>,
    pub confidence: Option<f64>,
    #[serde(default)]
    pub policy: Option<NpmFirewallDecisionPolicy>,
    #[serde(default)]
    pub authority: Option<NpmFirewallDecisionAuthority>,
    #[serde(default)]
    pub display: Option<NpmFirewallDecisionDisplay>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmFirewallAction {
    Allow,
    Warn,
    Block,
}

impl NpmFirewallAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallDecisionPolicy {
    pub group: String,
    pub key: Option<String>,
    pub intent: Option<String>,
    pub default_action: Option<NpmFirewallPolicyAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallDecisionAuthority {
    pub source: String,
    pub source_type: Option<String>,
    pub external_intel: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallDecisionDisplay {
    pub summary: Option<String>,
    pub report_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmFirewallPolicyAction {
    Allow,
    Warn,
    Block,
}

impl NpmFirewallPolicyAction {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "warn" => Some(Self::Warn),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmFirewallPolicyProfile {
    pub trusted_public_malicious_advisories: NpmFirewallPolicyAction,
    pub lpm_ai_confirmed_malware: NpmFirewallPolicyAction,
    pub lpm_ai_agent_control_surface: NpmFirewallPolicyAction,
    pub lpm_ai_suspicious: NpmFirewallPolicyAction,
    pub critical_vulnerability: NpmFirewallPolicyAction,
}

impl Default for NpmFirewallPolicyProfile {
    fn default() -> Self {
        Self {
            trusted_public_malicious_advisories: NpmFirewallPolicyAction::Block,
            lpm_ai_confirmed_malware: NpmFirewallPolicyAction::Block,
            lpm_ai_agent_control_surface: NpmFirewallPolicyAction::Warn,
            lpm_ai_suspicious: NpmFirewallPolicyAction::Warn,
            critical_vulnerability: NpmFirewallPolicyAction::Warn,
        }
    }
}

impl RegistryClient {
    pub async fn npm_firewall_batch_verdicts(
        &self,
        packages: &[NpmFirewallBatchPackage],
    ) -> Result<NpmFirewallBatchResponse, LpmError> {
        self.npm_firewall_batch_verdicts_with_posture(packages, AuthPosture::AuthRequired)
            .await
    }

    pub async fn npm_firewall_batch_verdicts_with_posture(
        &self,
        packages: &[NpmFirewallBatchPackage],
        posture: AuthPosture,
    ) -> Result<NpmFirewallBatchResponse, LpmError> {
        self.npm_firewall_batch_verdicts_with_posture_and_policy(packages, posture, None)
            .await
    }

    pub async fn npm_firewall_batch_verdicts_with_posture_and_policy(
        &self,
        packages: &[NpmFirewallBatchPackage],
        posture: AuthPosture,
        policy_profile: Option<NpmFirewallPolicyProfile>,
    ) -> Result<NpmFirewallBatchResponse, LpmError> {
        let url = format!("{}/api/registry/-/npm-firewall/verdicts", self.base_url);
        let mut request = serde_json::json!({
            "packages": packages,
            "decisionDetail": "actionable",
        });
        if let Some(policy_profile) = policy_profile {
            request["policyProfile"] = serde_json::json!({
                "policies": policy_profile,
            });
        }
        let body = serde_json::to_vec(&request).map_err(|error| {
            LpmError::Registry(format!(
                "failed to encode npm firewall verdict request: {error}"
            ))
        })?;
        let request_body_bytes = body.len() as u64;
        let total_started = std::time::Instant::now();
        let request_started = std::time::Instant::now();
        let response = self
            .execute_with_recovery(posture, || {
                let body = body.clone();
                let url = url.clone();
                async move {
                    let mut req = self
                        .http
                        .for_url(&url)
                        .await?
                        .post(&url)
                        .header("Accept", "application/json")
                        .header("Content-Type", "application/json")
                        .body(body);
                    if let Some(bearer) = self.current_bearer(posture) {
                        req = req.bearer_auth(bearer);
                    }
                    self.send_with_retry(req).await
                }
            })
            .await?;
        let request_ms = elapsed_millis(request_started);
        let (mut parsed, body_timings) = parse_capped_api_json_with_timing::<
            NpmFirewallBatchResponse,
        >(response, "npm firewall batch verdict response")
        .await?;
        parsed.client_timing = Some(NpmFirewallClientTiming {
            request_ms,
            body_read_ms: body_timings.body_read_ms,
            json_parse_ms: body_timings.json_parse_ms,
            total_ms: elapsed_millis(total_started),
            request_body_bytes,
            response_body_bytes: body_timings.body_bytes,
        });
        Ok(parsed)
    }
}
