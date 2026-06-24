use super::*;
use lpm_registry::client::{
    AuthPosture, NpmFirewallAction, NpmFirewallBatchPackage, NpmFirewallClientTiming,
    NpmFirewallDecision, NpmFirewallDiagnostics,
};

const ENV_EXPERIMENT_NPM_FIREWALL: &str = "LPM_EXPERIMENT_NPM_FIREWALL";
const ENV_EXPERIMENT_NPM_FIREWALL_LOOKUP: &str = "LPM_EXPERIMENT_NPM_FIREWALL_LOOKUP";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum NpmFirewallExperimentMode {
    #[default]
    Off,
    Report,
    Enforce,
}

impl NpmFirewallExperimentMode {
    pub(super) fn from_env() -> Self {
        Self::from_env_value(std::env::var(ENV_EXPERIMENT_NPM_FIREWALL).ok().as_deref())
    }

    pub(super) fn from_env_value(raw: Option<&str>) -> Self {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value)
                if value == "1"
                    || value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("enforce")
                    || value.eq_ignore_ascii_case("deny")
                    || value.eq_ignore_ascii_case("block") =>
            {
                Self::Enforce
            }
            Some(value)
                if value.eq_ignore_ascii_case("report") || value.eq_ignore_ascii_case("warn") =>
            {
                Self::Report
            }
            _ => Self::Off,
        }
    }

    pub(super) fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Report => "report",
            Self::Enforce => "enforce",
        }
    }

    pub(super) fn disables_tarball_prefetch(self) -> bool {
        self.is_enabled()
    }

    pub(super) fn auth_posture(self) -> AuthPosture {
        match self {
            Self::Off | Self::Report => AuthPosture::AnonymousPreferred,
            Self::Enforce => AuthPosture::AuthRequired,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum NpmFirewallLookupMode {
    #[default]
    PackageAndIntegrity,
    PackageOnly,
}

impl NpmFirewallLookupMode {
    pub(super) fn from_env() -> Self {
        Self::from_env_value(
            std::env::var(ENV_EXPERIMENT_NPM_FIREWALL_LOOKUP)
                .ok()
                .as_deref(),
        )
    }

    pub(super) fn from_env_value(raw: Option<&str>) -> Self {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value)
                if value.eq_ignore_ascii_case("package")
                    || value.eq_ignore_ascii_case("package-only")
                    || value.eq_ignore_ascii_case("package_only")
                    || value.eq_ignore_ascii_case("package-version")
                    || value.eq_ignore_ascii_case("package_version") =>
            {
                Self::PackageOnly
            }
            _ => Self::PackageAndIntegrity,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::PackageAndIntegrity => "package_and_integrity",
            Self::PackageOnly => "package_only",
        }
    }

    fn include_integrity(self) -> bool {
        matches!(self, Self::PackageAndIntegrity)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct NpmFirewallPreflightStats {
    pub(super) mode: NpmFirewallExperimentMode,
    pub(super) lookup_mode: NpmFirewallLookupMode,
    pub(super) checked_count: u64,
    pub(super) batch_ms: u128,
    pub(super) allow_count: u64,
    pub(super) warn_count: u64,
    pub(super) block_count: u64,
    pub(super) unknown_count: u64,
    pub(super) matched_count: u64,
    pub(super) rpc_failed: bool,
    pub(super) offline_skipped: bool,
    pub(super) worker_diagnostics: Option<NpmFirewallDiagnostics>,
    pub(super) client_timing: Option<NpmFirewallClientTiming>,
}

impl NpmFirewallPreflightStats {
    fn for_mode(mode: NpmFirewallExperimentMode) -> Self {
        Self {
            mode,
            lookup_mode: NpmFirewallLookupMode::from_env(),
            ..Self::default()
        }
    }

    pub(super) fn record_summary(&mut self, summary: lpm_registry::client::NpmFirewallSummary) {
        self.allow_count = summary.allow;
        self.warn_count = summary.warn;
        self.block_count = summary.block;
        self.unknown_count = summary.unknown;
        self.matched_count = summary.matched;
    }

    pub(super) fn record_worker_diagnostics(
        &mut self,
        diagnostics: Option<NpmFirewallDiagnostics>,
    ) {
        self.worker_diagnostics = diagnostics;
    }

    pub(super) fn record_client_timing(&mut self, timing: Option<NpmFirewallClientTiming>) {
        self.client_timing = timing;
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "enabled": self.mode.is_enabled(),
            "mode": self.mode.as_str(),
            "lookup_mode": self.lookup_mode.as_str(),
            "checked_count": self.checked_count,
            "batch_ms": self.batch_ms,
            "allow_count": self.allow_count,
            "warn_count": self.warn_count,
            "block_count": self.block_count,
            "unknown_count": self.unknown_count,
            "matched_count": self.matched_count,
            "rpc_failed": self.rpc_failed,
            "offline_skipped": self.offline_skipped,
        });
        if let Some(diagnostics) = &self.worker_diagnostics {
            json["worker"] = serde_json::to_value(diagnostics).unwrap_or(serde_json::Value::Null);
        }
        if let Some(timing) = &self.client_timing {
            json["client"] = serde_json::to_value(timing).unwrap_or(serde_json::Value::Null);
        }
        json
    }
}

pub(super) async fn run_npm_firewall_preflight(
    mode: NpmFirewallExperimentMode,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    packages: &[InstallPackage],
    offline: bool,
    json_output: bool,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    let mut stats = NpmFirewallPreflightStats::for_mode(mode);
    if !mode.is_enabled() {
        return Ok(stats);
    }

    let verdict_packages = npm_firewall_packages(packages, route_table, stats.lookup_mode);
    stats.checked_count = verdict_packages.len() as u64;
    if verdict_packages.is_empty() {
        return Ok(stats);
    }

    if offline {
        stats.offline_skipped = true;
        let message = format!(
            "npm firewall verdict preflight requires network access; unset {ENV_EXPERIMENT_NPM_FIREWALL} or run online"
        );
        if matches!(mode, NpmFirewallExperimentMode::Report) {
            if !json_output {
                output::warn(&format!(
                    "{message}; continuing because report mode is active"
                ));
            }
            return Ok(stats);
        }
        return Err(LpmError::Registry(message));
    }

    let started = Instant::now();
    let response = match client
        .npm_firewall_batch_verdicts_with_posture(&verdict_packages, mode.auth_posture())
        .await
    {
        Ok(response) => response,
        Err(error) if matches!(mode, NpmFirewallExperimentMode::Report) => {
            stats.batch_ms = started.elapsed().as_millis();
            stats.rpc_failed = true;
            if !json_output {
                output::warn(&format!(
                    "npm firewall verdict preflight failed in report mode: {error}"
                ));
            }
            return Ok(stats);
        }
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "npm firewall verdict preflight failed: {error}"
            )));
        }
    };
    stats.batch_ms = started.elapsed().as_millis();
    stats.record_summary(response.summary);
    stats.record_worker_diagnostics(response.diagnostics.clone());
    stats.record_client_timing(response.client_timing);
    tracing::debug!(
        target = "lpm::firewall",
        package_count = response.summary.total,
        matched = response.summary.matched,
        warn = response.summary.warn,
        block = response.summary.block,
        elapsed_ms = stats.batch_ms,
        request_id = %response.request_id,
        policy_mode = %response.policy_mode,
        "npm firewall verdict preflight completed",
    );

    let blocked: Vec<_> = response
        .decisions
        .iter()
        .filter(|decision| decision.action == NpmFirewallAction::Block)
        .collect();
    let warned: Vec<_> = response
        .decisions
        .iter()
        .filter(|decision| decision.action == NpmFirewallAction::Warn)
        .collect();

    if matches!(mode, NpmFirewallExperimentMode::Report) {
        if !json_output && (!blocked.is_empty() || !warned.is_empty()) {
            output::warn(&format!(
                "npm firewall report found {} blocked and {} warned package(s); install continues because report mode is active.",
                blocked.len(),
                warned.len()
            ));
            print_firewall_decisions(&blocked);
            print_firewall_decisions(&warned);
        }
        return Ok(stats);
    }

    if !warned.is_empty() && !json_output {
        output::warn(&format!(
            "npm firewall warned for {} package(s):",
            warned.len()
        ));
        print_firewall_decisions(&warned);
    }

    if blocked.is_empty() {
        return Ok(stats);
    }

    if !json_output {
        output::warn(&format!(
            "npm firewall blocked {} package(s):",
            blocked.len()
        ));
        print_firewall_decisions(&blocked);
    }
    Err(LpmError::Registry(format!(
        "{} package(s) blocked by LPM npm firewall",
        blocked.len()
    )))
}

pub(super) fn npm_firewall_packages(
    packages: &[InstallPackage],
    route_table: &RouteTable,
    lookup_mode: NpmFirewallLookupMode,
) -> Vec<NpmFirewallBatchPackage> {
    let mut verdict_packages = Vec::with_capacity(packages.len());
    for package in packages {
        if let Some(verdict_package) = npm_firewall_package(package, route_table, lookup_mode) {
            verdict_packages.push(verdict_package);
        }
    }
    verdict_packages
}

pub(super) fn npm_firewall_package(
    package: &InstallPackage,
    route_table: &RouteTable,
    lookup_mode: NpmFirewallLookupMode,
) -> Option<NpmFirewallBatchPackage> {
    let Ok(lpm_lockfile::Source::Registry { url }) = package.source_kind() else {
        return None;
    };
    if url.trim_end_matches('/') != lpm_common::NPM_REGISTRY_URL {
        return None;
    }
    if !matches!(
        route_table.route_for_package(&package.name),
        UpstreamRoute::NpmDirect
    ) {
        return None;
    }
    Some(NpmFirewallBatchPackage {
        name: package.name.clone(),
        version: package.version.clone(),
        integrity: lookup_mode
            .include_integrity()
            .then(|| package.integrity.clone())
            .flatten(),
        published_at: package.registry_published_at.clone(),
    })
}

fn print_firewall_decisions(decisions: &[&NpmFirewallDecision]) {
    for decision in decisions {
        let name = lpm_common::sanitize_for_terminal(&decision.name);
        let version = lpm_common::sanitize_for_terminal(&decision.version);
        let verdict = lpm_common::sanitize_for_terminal(&decision.verdict);
        let reason = lpm_common::sanitize_for_terminal(&decision.reason);
        eprintln!("    {name}@{version} - {verdict}: {reason}");
    }
}
