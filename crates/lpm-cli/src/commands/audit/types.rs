/// Compact counts produced by [`run_install_summary`] for the
/// audit-after-install line in the install pipeline. Intentionally
/// flat + Serialize-friendly so the install JSON envelope can attach
/// it as `audit_summary` without an extra mapping layer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditCounts {
    /// Total packages discovered + checked in this run.
    pub packages_audited: usize,
    /// OSV-reported vulnerabilities across the discovered tree.
    /// Matches the headline number `print_summary` shows so the
    /// install-time advisory and a follow-up `lpm audit` agree.
    pub vulnerabilities: usize,
    /// Packages flagged by client-side behavioral analysis
    /// (eval / child_process / dynamic require / etc.).
    pub suspicious: usize,
    /// Wall-clock spent inside `run_install_summary`.
    pub elapsed_ms: u128,
}

#[derive(Debug)]
pub(super) struct AuditResult {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) quality_score: Option<u32>,
    pub(super) issues: Vec<AuditIssue>,
}

#[derive(Debug)]
pub(super) struct AuditIssue {
    pub(super) severity: String,
    pub(super) message: String,
    pub(super) category: String,
    /// Where the issue was detected: "registry", "local", or "combined".
    pub(super) source: String,
}
