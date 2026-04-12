//! **Phase 32 Phase 7 — pure-function helpers for the interactive upgrade flow.**
//!
//! Everything in this module is an unbiased predicate or transformation
//! over data already in scope at the call site. There are no I/O calls,
//! no async, no global state. The unit tests cover every branch in
//! isolation, and the orchestrating `commands::upgrade::run` consumes
//! these helpers without needing wiremock or filesystem fixtures.

use crate::patch_engine;
use lpm_lockfile::Lockfile;
use lpm_registry::types::VersionMetadata;
use lpm_workspace::PatchedDependencyEntry;
use std::cmp::Ordering;
use std::collections::HashMap;

/// Compare an installed version against an upgrade target and classify
/// the change. The classification drives both the row color and the
/// default-check policy in the interactive multiselect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemverClass {
    Patch,
    Minor,
    Major,
    Prerelease,
    /// Catch-all for downgrades, version-parse failures, equal-version
    /// edge cases, and any future surprise. Always default-unchecked.
    Unknown,
}

impl SemverClass {
    /// The default-selection rule for the multiselect. Patches and minors
    /// are pre-checked; majors, prereleases, and unknowns are not.
    pub fn default_checked(self) -> bool {
        matches!(self, Self::Patch | Self::Minor)
    }
}

/// Classify the change between two versions. Returns `Unknown` for
/// downgrades or unparseable versions.
pub fn classify_semver_change(from: &str, to: &str) -> SemverClass {
    let (Ok(f), Ok(t)) = (
        lpm_semver::Version::parse(from),
        lpm_semver::Version::parse(to),
    ) else {
        return SemverClass::Unknown;
    };
    if t.is_prerelease() {
        return SemverClass::Prerelease;
    }
    match t.major().cmp(&f.major()) {
        Ordering::Greater => SemverClass::Major,
        Ordering::Less => SemverClass::Unknown,
        Ordering::Equal => match t.minor().cmp(&f.minor()) {
            Ordering::Greater => SemverClass::Minor,
            Ordering::Less => SemverClass::Unknown,
            Ordering::Equal => match t.patch().cmp(&f.patch()) {
                Ordering::Greater => SemverClass::Patch,
                _ => SemverClass::Unknown,
            },
        },
    }
}

/// True iff the upgrade target's published manifest declares any
/// non-empty `EXECUTED_INSTALL_PHASES` lifecycle script.
///
/// Reads from `VersionMetadata::lifecycle_scripts` (the LPM-extended
/// `_lifecycleScripts` field). Phase 7's `[!]` marker is gated on this
/// predicate — see design doc F-V8 for the rationale.
pub fn target_has_install_scripts(meta: &VersionMetadata) -> bool {
    let Some(scripts) = meta.lifecycle_scripts.as_ref() else {
        return false;
    };
    lpm_security::EXECUTED_INSTALL_PHASES
        .iter()
        .any(|phase| scripts.get(*phase).is_some_and(|body| !body.is_empty()))
}

/// Peer-dep satisfaction analysis for an upgrade candidate.
///
/// **D-design-1 audit fix (MEDIUM):** the `basis` field explicitly marks
/// that the analysis is against the CURRENT lockfile, not a projected
/// post-upgrade state. Recomputing against the proposed selection set is
/// deferred to Phase 7.x.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeerImpact {
    /// True iff all target peers are satisfied in the lockfile.
    pub ok: bool,
    /// Always `"current_lockfile"` in Phase 7.
    pub basis: String,
    /// Peer dependencies not present in the lockfile at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    /// Peer dependencies present but at an unsatisfying version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<PeerViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeerViolation {
    pub name: String,
    pub have: String,
    pub want: String,
}

/// Walk the target version's `peer_dependencies` and check each
/// declared peer against the lockfile. Returns a `PeerImpact` with
/// `ok: true` if every peer is satisfied.
///
/// Range parse failures are tolerated as satisfaction success so we
/// don't block an upgrade on an unparseable peer-dep range.
pub fn compute_peer_impact(
    target_peer_deps: &HashMap<String, String>,
    lockfile: Option<&Lockfile>,
) -> PeerImpact {
    if target_peer_deps.is_empty() {
        return PeerImpact {
            ok: true,
            basis: "current_lockfile".into(),
            missing: vec![],
            violations: vec![],
        };
    }
    let mut violations: Vec<PeerViolation> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for (peer_name, want_range) in target_peer_deps {
        let installed = lockfile
            .and_then(|lf| lf.find_package(peer_name))
            .map(|p| p.version.clone());
        match installed {
            None => missing.push(peer_name.clone()),
            Some(have) => {
                if !range_satisfies(want_range, &have) {
                    violations.push(PeerViolation {
                        name: peer_name.clone(),
                        have,
                        want: want_range.clone(),
                    });
                }
            }
        }
    }
    let ok = violations.is_empty() && missing.is_empty();
    PeerImpact {
        ok,
        basis: "current_lockfile".into(),
        missing,
        violations,
    }
}

/// Parse `range_str` as a semver range and check whether `version_str`
/// satisfies it. Returns `true` on parse failure (conservative: don't
/// block upgrades on unparseable peer ranges).
fn range_satisfies(range_str: &str, version_str: &str) -> bool {
    let Ok(range) = lpm_semver::VersionReq::parse(range_str) else {
        tracing::debug!(
            "could not parse peer-dep range {:?} — treating as satisfied",
            range_str
        );
        return true;
    };
    let Ok(version) = lpm_semver::Version::parse(version_str) else {
        tracing::debug!(
            "could not parse version {:?} — treating as satisfied",
            version_str
        );
        return true;
    };
    range.matches(&version)
}

/// Patch-invalidation analysis for an upgrade candidate.
///
/// Phase 7 ships the **selector-orphan** check only — see design doc
/// F-V10 for why the stronger integrity-rotation check is deferred.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PatchInvalidation {
    /// The raw key in `lpm.patchedDependencies` that this upgrade would
    /// orphan (e.g., `"lodash@4.17.20"`).
    pub key: String,
    /// The patch file path declared in the entry.
    pub patch_path: String,
    pub from_version: String,
    pub to_version: String,
}

/// Detect whether upgrading `candidate_name` from `candidate_from_version`
/// to `candidate_to_version` would orphan a `lpm.patchedDependencies` entry.
pub fn detect_patch_invalidation(
    patches: &HashMap<String, PatchedDependencyEntry>,
    candidate_name: &str,
    candidate_from_version: &str,
    candidate_to_version: &str,
) -> Option<PatchInvalidation> {
    if candidate_from_version == candidate_to_version {
        return None;
    }
    for (raw_key, entry) in patches {
        let Ok((pname, pver)) = patch_engine::parse_patch_key(raw_key) else {
            continue;
        };
        if pname == candidate_name && pver == candidate_from_version {
            return Some(PatchInvalidation {
                key: raw_key.clone(),
                patch_path: entry.path.clone(),
                from_version: candidate_from_version.to_string(),
                to_version: candidate_to_version.to_string(),
            });
        }
    }
    None
}

/// True iff the multiselect should pre-check this candidate's row.
/// Patch and Minor are pre-checked; everything else is not.
pub fn default_pre_check(
    class: SemverClass,
    _has_install_scripts: bool,
    _peer_impact: &PeerImpact,
    _patch_invalidation: Option<&PatchInvalidation>,
) -> bool {
    class.default_checked()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_semver_change ────────────────────────────────────────

    #[test]
    fn classify_returns_patch_for_z_bump() {
        assert_eq!(classify_semver_change("1.2.0", "1.2.4"), SemverClass::Patch);
    }

    #[test]
    fn classify_returns_minor_for_y_bump() {
        assert_eq!(classify_semver_change("1.2.0", "1.5.0"), SemverClass::Minor);
    }

    #[test]
    fn classify_returns_major_for_x_bump() {
        assert_eq!(classify_semver_change("1.2.0", "2.0.0"), SemverClass::Major);
    }

    #[test]
    fn classify_returns_prerelease_when_to_is_pre() {
        assert_eq!(
            classify_semver_change("1.2.0", "2.0.0-rc.1"),
            SemverClass::Prerelease
        );
    }

    #[test]
    fn classify_returns_unknown_for_downgrade() {
        assert_eq!(
            classify_semver_change("2.0.0", "1.5.0"),
            SemverClass::Unknown
        );
    }

    #[test]
    fn classify_returns_unknown_for_unparseable() {
        assert_eq!(
            classify_semver_change("not.a.ver", "also.bad"),
            SemverClass::Unknown
        );
    }

    #[test]
    fn classify_returns_unknown_for_equal_versions() {
        assert_eq!(
            classify_semver_change("1.2.0", "1.2.0"),
            SemverClass::Unknown
        );
    }

    // ── SemverClass::default_checked ─────────────────────────────────

    #[test]
    fn default_checked_only_patch_and_minor() {
        assert!(SemverClass::Patch.default_checked());
        assert!(SemverClass::Minor.default_checked());
        assert!(!SemverClass::Major.default_checked());
        assert!(!SemverClass::Prerelease.default_checked());
        assert!(!SemverClass::Unknown.default_checked());
    }

    // ── target_has_install_scripts ───────────────────────────────────

    fn make_meta(scripts: Option<HashMap<String, String>>) -> VersionMetadata {
        VersionMetadata {
            lifecycle_scripts: scripts,
            ..Default::default()
        }
    }

    #[test]
    fn install_scripts_true_for_postinstall() {
        let mut s = HashMap::new();
        s.insert("postinstall".into(), "node x.js".into());
        assert!(target_has_install_scripts(&make_meta(Some(s))));
    }

    #[test]
    fn install_scripts_true_for_preinstall() {
        let mut s = HashMap::new();
        s.insert("preinstall".into(), "echo hi".into());
        assert!(target_has_install_scripts(&make_meta(Some(s))));
    }

    #[test]
    fn install_scripts_true_for_install() {
        let mut s = HashMap::new();
        s.insert("install".into(), "make build".into());
        assert!(target_has_install_scripts(&make_meta(Some(s))));
    }

    #[test]
    fn install_scripts_false_when_empty_body() {
        let mut s = HashMap::new();
        s.insert("postinstall".into(), "".into());
        assert!(!target_has_install_scripts(&make_meta(Some(s))));
    }

    #[test]
    fn install_scripts_false_when_only_unrelated_phases() {
        let mut s = HashMap::new();
        s.insert("prepare".into(), "tsc".into());
        assert!(!target_has_install_scripts(&make_meta(Some(s))));
    }

    #[test]
    fn install_scripts_false_when_field_missing() {
        assert!(!target_has_install_scripts(&make_meta(None)));
    }

    // ── compute_peer_impact ──────────────────────────────────────────

    fn make_lockfile(entries: &[(&str, &str)]) -> Lockfile {
        let mut lf = Lockfile::new();
        for (name, version) in entries {
            lf.add_package(lpm_lockfile::LockedPackage {
                name: name.to_string(),
                version: version.to_string(),
                source: None,
                integrity: None,
                dependencies: vec![],
            });
        }
        lf
    }

    #[test]
    fn peer_impact_ok_when_all_satisfied() {
        let lf = make_lockfile(&[("react", "18.2.0")]);
        let mut peers = HashMap::new();
        peers.insert("react".into(), "^18.0.0".into());
        let impact = compute_peer_impact(&peers, Some(&lf));
        assert!(impact.ok);
        assert_eq!(impact.basis, "current_lockfile");
    }

    #[test]
    fn peer_impact_missing_when_absent() {
        let lf = make_lockfile(&[]);
        let mut peers = HashMap::new();
        peers.insert("react".into(), "^18.0.0".into());
        let impact = compute_peer_impact(&peers, Some(&lf));
        assert!(!impact.ok);
        assert_eq!(impact.missing, vec!["react"]);
    }

    #[test]
    fn peer_impact_violation_when_mismatch() {
        let lf = make_lockfile(&[("react", "17.0.2")]);
        let mut peers = HashMap::new();
        peers.insert("react".into(), "^18.0.0".into());
        let impact = compute_peer_impact(&peers, Some(&lf));
        assert!(!impact.ok);
        assert_eq!(impact.violations.len(), 1);
        assert_eq!(impact.violations[0].name, "react");
        assert_eq!(impact.violations[0].have, "17.0.2");
        assert_eq!(impact.violations[0].want, "^18.0.0");
    }

    #[test]
    fn peer_impact_ok_when_no_peers() {
        let impact = compute_peer_impact(&HashMap::new(), Some(&make_lockfile(&[])));
        assert!(impact.ok);
    }

    #[test]
    fn peer_impact_ok_when_lockfile_none_and_no_peers() {
        let impact = compute_peer_impact(&HashMap::new(), None);
        assert!(impact.ok);
    }

    #[test]
    fn peer_impact_missing_when_no_lockfile_and_peers_declared() {
        let mut peers = HashMap::new();
        peers.insert("react".into(), "^18.0.0".into());
        let impact = compute_peer_impact(&peers, None);
        assert!(!impact.ok);
        assert_eq!(impact.missing, vec!["react"]);
    }

    #[test]
    fn peer_impact_tolerates_unparseable_range() {
        let lf = make_lockfile(&[("react", "18.2.0")]);
        let mut peers = HashMap::new();
        peers.insert("react".into(), ">>=18".into()); // garbage
        let impact = compute_peer_impact(&peers, Some(&lf));
        // Unparseable range → treated as satisfied
        assert!(impact.ok);
    }

    #[test]
    fn peer_impact_basis_is_always_current_lockfile() {
        // D-design-1 MEDIUM fix: basis field is always "current_lockfile"
        let impact = compute_peer_impact(&HashMap::new(), None);
        assert_eq!(impact.basis, "current_lockfile");
        let lf = make_lockfile(&[("react", "17.0.0")]);
        let mut peers = HashMap::new();
        peers.insert("react".into(), "^18.0.0".into());
        let impact = compute_peer_impact(&peers, Some(&lf));
        assert_eq!(impact.basis, "current_lockfile");
    }

    // ── detect_patch_invalidation ────────────────────────────────────

    fn patch_entry(path: &str) -> PatchedDependencyEntry {
        PatchedDependencyEntry {
            path: path.into(),
            original_integrity: "sha512-test".into(),
        }
    }

    #[test]
    fn patch_invalidation_returns_some_when_key_orphans() {
        let mut patches = HashMap::new();
        patches.insert("lodash@4.17.20".into(), patch_entry("patches/lodash.patch"));
        let result = detect_patch_invalidation(&patches, "lodash", "4.17.20", "4.17.21");
        assert!(result.is_some());
        let inv = result.unwrap();
        assert_eq!(inv.key, "lodash@4.17.20");
        assert_eq!(inv.from_version, "4.17.20");
        assert_eq!(inv.to_version, "4.17.21");
    }

    #[test]
    fn patch_invalidation_returns_none_when_versions_unchanged() {
        let mut patches = HashMap::new();
        patches.insert("lodash@4.17.20".into(), patch_entry("patches/lodash.patch"));
        let result = detect_patch_invalidation(&patches, "lodash", "4.17.20", "4.17.20");
        assert!(result.is_none());
    }

    #[test]
    fn patch_invalidation_returns_none_when_no_matching_key() {
        let mut patches = HashMap::new();
        patches.insert("sharp@1.0.0".into(), patch_entry("patches/sharp.patch"));
        let result = detect_patch_invalidation(&patches, "lodash", "4.17.20", "4.17.21");
        assert!(result.is_none());
    }

    #[test]
    fn patch_invalidation_handles_scoped_names() {
        let mut patches = HashMap::new();
        patches.insert(
            "@types/node@20.0.0".into(),
            patch_entry("patches/types-node.patch"),
        );
        let result = detect_patch_invalidation(&patches, "@types/node", "20.0.0", "20.10.0");
        assert!(result.is_some());
        assert_eq!(result.unwrap().key, "@types/node@20.0.0");
    }

    #[test]
    fn patch_invalidation_skips_malformed_keys() {
        let mut patches = HashMap::new();
        patches.insert("!!!bogus!!!".into(), patch_entry("patches/bogus.patch"));
        patches.insert("lodash@4.17.20".into(), patch_entry("patches/lodash.patch"));
        let result = detect_patch_invalidation(&patches, "lodash", "4.17.20", "4.17.21");
        assert!(result.is_some());
        assert_eq!(result.unwrap().key, "lodash@4.17.20");
    }

    // ── default_pre_check ────────────────────────────────────────────

    #[test]
    fn default_pre_check_follows_class_rule() {
        let ok_impact = PeerImpact {
            ok: true,
            basis: "current_lockfile".into(),
            missing: vec![],
            violations: vec![],
        };
        assert!(default_pre_check(
            SemverClass::Patch,
            false,
            &ok_impact,
            None
        ));
        assert!(default_pre_check(
            SemverClass::Minor,
            false,
            &ok_impact,
            None
        ));
        assert!(!default_pre_check(
            SemverClass::Major,
            false,
            &ok_impact,
            None
        ));
        assert!(!default_pre_check(
            SemverClass::Prerelease,
            false,
            &ok_impact,
            None
        ));
        assert!(!default_pre_check(
            SemverClass::Unknown,
            false,
            &ok_impact,
            None
        ));
        // Install scripts don't affect default check in Phase 7
        assert!(default_pre_check(
            SemverClass::Patch,
            true,
            &ok_impact,
            None
        ));
    }
}
