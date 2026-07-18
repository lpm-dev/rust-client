use lpm_common::LpmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum AuditLevel {
    #[value(alias = "low")]
    Info,
    #[value(alias = "medium")]
    Moderate,
    High,
    Critical,
}

/// Convert a severity string to a numeric level for comparison.
/// Higher = more severe.
pub(super) fn severity_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "moderate" | "medium" => 2,
        "info" | "low" => 1,
        _ => 0,
    }
}

/// Get the minimum severity level from a --level flag value.
pub(super) fn min_severity_level(level: AuditLevel) -> u8 {
    match level {
        AuditLevel::Critical => 4,
        AuditLevel::High => 3,
        AuditLevel::Moderate => 2,
        AuditLevel::Info => 1,
    }
}

// ─── Main audit entry point ─────────────────────────────────────────────────

/// CI exit code policy for `--fail-on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailPolicy {
    /// Exit non-zero only for confirmed vulnerabilities (OSV/registry).
    Vuln,
    /// Exit non-zero only for critical/high behavioral flags.
    Behavior,
    /// Exit non-zero only for hardcoded secret findings from `--secrets` mode.
    Secrets,
    /// Exit non-zero for either (default).
    All,
}

impl FailPolicy {
    pub(super) fn parse(s: &str) -> Result<Self, LpmError> {
        match s.to_lowercase().as_str() {
            "vuln" | "vulnerability" | "vulnerabilities" => Ok(Self::Vuln),
            "behavior" | "behavioral" | "behaviour" => Ok(Self::Behavior),
            "secret" | "secrets" => Ok(Self::Secrets),
            "all" => Ok(Self::All),
            _ => Err(LpmError::Registry(format!(
                "invalid --fail-on value '{s}'. Expected: vuln, behavior, secrets, or all"
            ))),
        }
    }
}
