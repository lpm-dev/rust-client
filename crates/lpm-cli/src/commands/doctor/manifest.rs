use crate::doctor_catalog;

use super::check::Check;

/// Run the shared manifest-compat detector against the workspace root
/// manifest and surface each finding as its own coded `Check::warn`.
///
/// Source of truth: [`lpm_workspace::PackageJson::manifest_compat_issues`].
/// The same detector drives the install-time stderr warnings emitted
/// from `engine_check::enforce`, so the human surface and the JSON
/// surface always agree.
///
/// Returns an empty Vec when there are no issues, when there's no
/// workspace root (`lpm add` plain-source-copy edge case), or when the
/// manifest is unreadable / malformed (other doctor checks already
/// flag those — adding a duplicate failure here would be noise).
///
/// Each issue's `code` is preserved verbatim as the `Check.code`, so
/// `lpm doctor --json` consumers can match on `pnpm_overrides_drift`,
/// `engines_pnpm_ignored`, etc.
pub(super) fn check_manifest_compat(root_package: &lpm_workspace::PackageJson) -> Vec<Check> {
    root_package
        .manifest_compat_issues()
        .into_iter()
        .filter_map(|issue| {
            let entry = match doctor_catalog::manifest_compat_entry(issue.code) {
                Some(entry) => entry,
                None => {
                    // Orphan code: lpm-workspace declared a new
                    // manifest-compat code without a matching CLI-side
                    // wrapper in `MANIFEST_COMPAT_ENTRIES`. The
                    // cross-crate parity test in `lpm-cli`
                    // (`manifest_compat_entries_cover_workspace_catalog`)
                    // pins this at unit-test time; the `debug_assert!`
                    // here is a runtime tripwire so debug builds fail
                    // loudly if the parity test is ever bypassed.
                    debug_assert!(
                        false,
                        "orphan manifest-compat code `{}` — \
                         `lpm_workspace::MANIFEST_COMPAT_CATALOG` declares it \
                         but `lpm_cli::doctor_catalog::MANIFEST_COMPAT_ENTRIES` \
                         is missing the corresponding `pub static CheckEntry` \
                         wrapper. Add the wrapper or `lpm doctor` will \
                         silently drop the issue.",
                        issue.code,
                    );
                    return None;
                }
            };
            let detail = format!("{}. {}", issue.detail, issue.remediation);
            let check = match issue.severity {
                lpm_workspace::ManifestCompatSeverity::Warn => Check::warn(entry, &detail),
                lpm_workspace::ManifestCompatSeverity::Info => Check::pass(entry, &detail),
            };
            Some(check)
        })
        .collect()
}
