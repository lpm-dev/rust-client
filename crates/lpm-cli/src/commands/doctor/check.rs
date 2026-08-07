use crate::doctor_catalog::{CheckEntry, DoctorFix, Severity};
use crate::install_ui;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum FixTarget {
    NodeSpec(String),
    BunSpec(String),
    TunnelDomain(String),
    PluginName(String),
}

impl FixTarget {
    fn supports(&self, action: DoctorFix) -> bool {
        matches!(
            (self, action),
            (
                Self::NodeSpec(_),
                DoctorFix::InstallNodeSpec | DoctorFix::InstallNode22
            ) | (Self::BunSpec(_), DoctorFix::InstallBunSpec)
                | (Self::TunnelDomain(_), DoctorFix::ClaimTunnel)
                | (Self::PluginName(_), DoctorFix::UpdatePlugin)
        )
    }
}

/// Check result emitted by `lpm doctor`.
///
/// Carries a typed reference to a [`CheckEntry`] from
/// [`crate::doctor_catalog`] — every emitted code is, by
/// construction, a registered catalog entry. The constructor
/// `debug_assert!`s that the chosen severity is one the catalog
/// declares the code can take, so wording-and-severity drift cannot
/// silently slip in.
///
/// `name` and `code` flow from the entry; only `detail` and
/// `severity` are runtime-owned.
pub(super) struct Check {
    /// Reference to the canonical catalog entry. `code` and `name`
    /// flow from here.
    pub(super) entry: &'static CheckEntry,
    pub(super) passed: bool,
    pub(super) detail: String,
    pub(super) severity: Severity,
    pub(super) fix_target: Option<FixTarget>,
}

impl Check {
    pub(super) fn pass(entry: &'static CheckEntry, detail: &str) -> Self {
        debug_assert!(
            entry.permits(Severity::Pass),
            "catalog entry `{}` does not permit Pass — declared severities: {:?}",
            entry.code,
            entry.possible_severities,
        );
        Self::new(entry, true, detail, Severity::Pass, None)
    }

    pub(super) fn fail(entry: &'static CheckEntry, detail: &str) -> Self {
        debug_assert!(
            entry.permits(Severity::Fail),
            "catalog entry `{}` does not permit Fail — declared severities: {:?}",
            entry.code,
            entry.possible_severities,
        );
        Self::new(entry, false, detail, Severity::Fail, None)
    }

    pub(super) fn warn(entry: &'static CheckEntry, detail: &str) -> Self {
        debug_assert!(
            entry.permits(Severity::Warn),
            "catalog entry `{}` does not permit Warn — declared severities: {:?}",
            entry.code,
            entry.possible_severities,
        );
        Self::new(entry, true, detail, Severity::Warn, None)
    }

    pub(super) fn fail_with_fix_target(
        entry: &'static CheckEntry,
        detail: &str,
        target: FixTarget,
    ) -> Self {
        debug_assert!(entry.permits(Severity::Fail));
        Self::new(entry, false, detail, Severity::Fail, Some(target))
    }

    pub(super) fn warn_with_fix_target(
        entry: &'static CheckEntry,
        detail: &str,
        target: FixTarget,
    ) -> Self {
        debug_assert!(entry.permits(Severity::Warn));
        Self::new(entry, true, detail, Severity::Warn, Some(target))
    }

    fn new(
        entry: &'static CheckEntry,
        passed: bool,
        detail: &str,
        severity: Severity,
        fix_target: Option<FixTarget>,
    ) -> Self {
        debug_assert!(
            match (entry.auto_fix, fix_target.as_ref()) {
                (Some(action), Some(target)) => target.supports(action),
                (Some(action), None) => !action.requires_target(),
                (None, None) => true,
                (None, Some(_)) => false,
            },
            "catalog action and runtime target disagree for `{}`",
            entry.code,
        );
        Self {
            entry,
            passed,
            detail: detail.into(),
            severity,
            fix_target,
        }
    }

    /// Stable machine-readable identifier — match on this in
    /// automation. Flat accessor over `entry.code` so the JSON
    /// serializer and human renderer don't need to reach through
    /// the catalog reference.
    pub(super) fn code(&self) -> &'static str {
        self.entry.code
    }

    /// Human-readable label. Flat accessor over `entry.name`.
    pub(super) fn name(&self) -> &'static str {
        self.entry.name
    }
}

#[cfg(test)]
fn format_doctor_issue_summary(failed: usize, warned: usize) -> String {
    let failure_word = if failed == 1 { "failure" } else { "failures" };
    let warning_word = if warned == 1 { "warning" } else { "warnings" };
    format!("{failed} {failure_word} and {warned} {warning_word}")
}

pub(super) fn format_doctor_issue_summary_colored(failed: usize, warned: usize) -> String {
    let failure_word = if failed == 1 { "failure" } else { "failures" };
    let warning_word = if warned == 1 { "warning" } else { "warnings" };
    format!(
        "{} {failure_word} and {} {warning_word}",
        install_ui::red(&failed.to_string()),
        install_ui::section(&warned.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog;

    #[test]
    fn check_pass_sets_passed_true() {
        let c = Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok");
        assert_eq!(c.code(), "registry_reachable");
        assert!(c.passed);
        assert!(matches!(c.severity, Severity::Pass));
    }

    #[test]
    fn check_fail_sets_passed_false() {
        let c = Check::fail(&doctor_catalog::REGISTRY_UNREACHABLE, "bad");
        assert_eq!(c.code(), "registry_unreachable");
        assert!(!c.passed);
        assert!(matches!(c.severity, Severity::Fail));
    }

    #[test]
    fn check_warn_sets_passed_true_but_severity_warn() {
        let c = Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "meh");
        assert_eq!(c.code(), "deps_sync_drift");
        assert!(c.passed);
        assert!(matches!(c.severity, Severity::Warn));
    }

    #[test]
    fn doctor_issue_summary_uses_singular_words_for_one_each() {
        assert_eq!(format_doctor_issue_summary(1, 1), "1 failure and 1 warning");
        assert_eq!(
            format_doctor_issue_summary(2, 0),
            "2 failures and 0 warnings"
        );
    }

    /// Codes flow from the catalog entry, never the call site.
    /// Verifies every constructor exposes a non-empty code via the
    /// `code()` method, mirroring the contract pinned by the
    /// `lpm doctor --json` workflow test.
    #[test]
    fn check_constructors_expose_non_empty_code_from_catalog() {
        let p = Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "");
        let f = Check::fail(&doctor_catalog::AUTH_INVALID, "");
        let w = Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "");
        for c in [&p, &f, &w] {
            assert!(!c.code().is_empty(), "every check needs a non-empty code");
        }
    }

    #[test]
    fn warning_count_with_mixed_checks() {
        let checks = [
            Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok"),
            Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "meh"),
            Check::fail(&doctor_catalog::AUTH_INVALID, "bad"),
            Check::warn(&doctor_catalog::LOCKFILE_MISSING, "meh2"),
        ];

        let warning_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert_eq!(warning_count, 2);
        assert_eq!(failed_count, 1);
        assert!(!no_failures); // fail check makes no_failures false
        assert!(has_warnings);
        assert!(!clean);
    }

    #[test]
    fn no_failures_true_with_warnings_but_clean_false() {
        // Warnings don't count as failures, but the run is not "clean"
        let checks = [
            Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok"),
            Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "meh"),
        ];
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert!(no_failures);
        assert!(has_warnings);
        assert!(!clean);
    }

    #[test]
    fn clean_true_only_when_all_pass_no_warnings() {
        let checks = [
            Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok"),
            Check::pass(&doctor_catalog::AUTH_VALID, "fine"),
        ];
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert!(no_failures);
        assert!(!has_warnings);
        assert!(clean);
    }
}
