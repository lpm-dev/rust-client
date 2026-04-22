//! **Phase 46 P7 — pure version-diff core.**
//!
//! Computes the field-by-field diff between a prior-approved
//! [`TrustedDependencyBinding`] and a candidate [`BlockedPackage`]
//! across the three dimensions [§11 P7] calls out: script hash,
//! behavioral-tag set, and provenance identity tuple.
//!
//! ## Shape
//!
//! Pure functions over [`TrustedDependencyBinding`] and
//! [`BlockedPackage`]. No I/O, no registry calls, no stdout writes.
//! The [`VersionDiff`] + [`VersionDiffReason`] types mirror P6's
//! `TrustReason` split — decision is lifted out of the rendering
//! layer so unit tests can assert the classification without
//! capturing stdout, and the JSON output path (C4) can serialize
//! the same structure agents consume.
//!
//! ## Drift dimensions
//!
//! 1. **Script hash.** `TrustedDependencyBinding.script_hash` ==
//!    `BlockedPackage.script_hash`. Unknown on either side (`None`)
//!    is treated as "no signal" — the install-time binding may have
//!    been approved before the field was captured.
//! 2. **Behavioral tags.** `TrustedDependencyBinding.behavioral_tags_hash`
//!    compared fast; if the hashes differ, `.behavioral_tags` is
//!    compared as a set to produce the `gained / lost` delta the
//!    rendering layer surfaces (§11 P7 ship criterion 2).
//! 3. **Provenance identity.** Uses the SAME identity tuple
//!    (`present + publisher + workflow_path`) as
//!    `lpm_security::provenance::check_provenance_drift`, so the
//!    diff UI cannot disagree with the install-time drift gate on
//!    which dimension rotated.
//!
//! ## Prior-binding lookup
//!
//! This module DOES NOT resolve the prior version — callers pass the
//! `(prior_version, binding)` tuple obtained from
//! [`TrustedDependencies::latest_binding_for_name`]. The selector
//! discipline lives in `lpm-workspace` so P4's drift gate and P7's
//! diff can never select a different "prior approval."
//!
//! [`TrustedDependencyBinding`]: lpm_workspace::TrustedDependencyBinding
//! [`BlockedPackage`]: crate::build_state::BlockedPackage
//! [`TrustedDependencies::latest_binding_for_name`]: lpm_workspace::TrustedDependencies::latest_binding_for_name
//! [§11 P7]: https://github.com/anthropics/claude-code — see plan-doc §11 P7

use crate::build_state::BlockedPackage;
use lpm_workspace::{ProvenanceSnapshot, TrustedDependencyBinding};

/// The per-dimension classification of a version diff.
///
/// Multi-field drift collapses into [`Self::MultiFieldDrift`] rather
/// than enumerating every subset, because the rendering layer (C2 +
/// C3) and the JSON output (C4) surface each present dimension
/// independently — the enum is the routing decision, not the
/// per-dimension flag.
///
/// Ordering principle: more-surprising reasons sort later so a
/// future `worse_of`-style reduction can be added without a breaking
/// re-shuffle. Today only [`Self::NoChange`] is the terminal "don't
/// render" verdict; all others render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionDiffReason {
    /// None of the three dimensions drifted (or every one that did
    /// was `None`-vs-`None` = no signal). The rendering layer omits
    /// the diff card entirely. This is NOT the same as "fields are
    /// missing" — `NoChange` is a positive equality assertion on
    /// every dimension we can compare.
    NoChange,
    /// Only the script hash drifted between approved and candidate.
    /// Script bodies live in the store; the rendering layer reads
    /// them and produces a unified diff (that's a C2/C3 concern —
    /// this module only records the verdict).
    ScriptHashDrift,
    /// Only the behavioral-tag set drifted. `gained` / `lost` are
    /// the set-difference deltas, sorted lexicographically (matches
    /// `active_tag_names()` ordering) so output is deterministic.
    ///
    /// At least one of `gained` / `lost` is non-empty when this
    /// variant is returned — the `NoChange` case is filtered out
    /// upstream in [`compute_version_diff`].
    BehavioralTagShift {
        gained: Vec<String>,
        lost: Vec<String>,
    },
    /// Only the provenance identity tuple drifted. `kind`
    /// distinguishes the three meaningful cases — see
    /// [`ProvenanceDriftKind`].
    ProvenanceDrift { kind: ProvenanceDriftKind },
    /// Two or more dimensions drifted simultaneously. Each
    /// sub-verdict is present so the rendering layer can produce
    /// one card section per dimension without re-running the
    /// per-dimension check.
    MultiFieldDrift {
        script_hash: bool,
        tags: Option<TagShift>,
        provenance: Option<ProvenanceDriftKind>,
    },
}

/// Per-dimension behavioral-tag shift payload, shared between
/// [`VersionDiffReason::BehavioralTagShift`] and the multi-field
/// branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagShift {
    /// Tags present in the candidate but NOT in the prior-approved
    /// binding. Sorted lex.
    pub gained: Vec<String>,
    /// Tags present in the prior-approved binding but NOT in the
    /// candidate. Sorted lex.
    pub lost: Vec<String>,
}

/// How the provenance identity rotated.
///
/// Mirrors the `(approved, now)` match arms in
/// `lpm_security::provenance::check_provenance_drift` but EXPANDS
/// the `(None-side, Some-side)` cases so the rendering layer can
/// say "this version NEWLY has provenance" vs. "this version DROPPED
/// provenance" explicitly. The drift gate collapses
/// `Some(!present) + Some(present)` to `NoDrift` because present →
/// better; P7's UI still surfaces it as informational context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceDriftKind {
    /// Approved side had provenance with identity `X`; candidate has
    /// provenance with identity `Y`. The identity tuple is
    /// `(present, publisher, workflow_path)` — `workflow_ref` and
    /// `attestation_cert_sha256` rotate per release and are excluded
    /// (same discipline as `identity_equal` in lpm-security).
    IdentityChanged,
    /// Approved side had provenance, candidate does NOT. The axios
    /// 1.14.1 pattern.
    Dropped,
    /// Approved side had no provenance attestation, candidate has
    /// one. The package "gained" provenance — informational only;
    /// `check_provenance_drift` treats this as `NoDrift`.
    Gained,
}

/// A computed version diff between a prior-approved binding and a
/// candidate `BlockedPackage`.
///
/// Callers typically:
/// 1. Look up the prior binding via
///    [`TrustedDependencies::latest_binding_for_name`].
/// 2. Pass `(prior_version, binding, candidate)` into
///    [`compute_version_diff`].
/// 3. Branch on `reason` to decide whether to render.
///
/// [`TrustedDependencies::latest_binding_for_name`]: lpm_workspace::TrustedDependencies::latest_binding_for_name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDiff {
    /// The version string of the prior-approved binding (e.g. `"1.14.0"`).
    /// Rendered in the human UI as `"since v1.14.0"`.
    pub prior_version: String,
    /// The candidate version string the diff is computed against.
    pub candidate_version: String,
    /// The classification. [`VersionDiffReason::NoChange`] means
    /// callers should suppress any diff rendering — no dimension
    /// drifted.
    pub reason: VersionDiffReason,
}

impl VersionDiff {
    /// Convenience predicate — `true` when at least one dimension
    /// actually drifted. Mirrors the `!matches!(reason, NoChange)`
    /// pattern so render-sites can read as `if diff.is_drift()`.
    pub fn is_drift(&self) -> bool {
        !matches!(self.reason, VersionDiffReason::NoChange)
    }
}

/// Identity tuple used for provenance comparison.
///
/// Mirrors `lpm_security::provenance::identity_equal` EXACTLY so the
/// diff UI's equality decision cannot diverge from the install-time
/// drift gate's equality decision. Keeping the comparison local (a
/// pure helper) rather than re-exporting the security crate's
/// private fn avoids a public-API leak from `lpm-security` just to
/// satisfy a rendering consumer.
fn provenance_identity_equal(a: &ProvenanceSnapshot, b: &ProvenanceSnapshot) -> bool {
    a.present == b.present && a.publisher == b.publisher && a.workflow_path == b.workflow_path
}

/// Classify a single provenance dimension given the `(approved,
/// candidate)` snapshots.
///
/// Returns `None` for the "no signal" cases where the diff UI should
/// stay silent:
/// - Neither side has a captured snapshot (both `None`).
/// - Approved has no snapshot but candidate does — this IS the
///   "Gained" case and returns `Some(Gained)`; the rendering layer
///   decides whether to surface it.
///
/// The full match table:
///
/// | approved     | candidate                        | verdict                                  |
/// |--------------|----------------------------------|------------------------------------------|
/// | `None`       | `None`                           | `None` (no signal)                       |
/// | `None`       | `Some(_ present = _)`            | `Some(Gained)` if present=true else `None` |
/// | `Some(_ present = true)` | `None`                | `Some(Dropped)`                          |
/// | `Some(_ present = true)` | `Some(_ present = false)` | `Some(Dropped)`                      |
/// | `Some(_ present = false)` | `Some(_ present = true)` | `Some(Gained)`                      |
/// | `Some(a)` | `Some(b)` (both present, identity eq)   | `None` (no change)                       |
/// | `Some(a)` | `Some(b)` (both present, identity neq)  | `Some(IdentityChanged)`                  |
/// | `Some(_ absent)` | `Some(_ absent)` / `None`            | `None` (no signal — never had it)        |
fn classify_provenance(
    approved: Option<&ProvenanceSnapshot>,
    candidate: Option<&ProvenanceSnapshot>,
) -> Option<ProvenanceDriftKind> {
    match (approved, candidate) {
        // Both absent → no signal.
        (None, None) => None,

        // Approved none, candidate something.
        (None, Some(c)) => {
            if c.present {
                Some(ProvenanceDriftKind::Gained)
            } else {
                // Candidate is `Some(present=false)` — the install
                // pipeline captured "no attestation" rather than
                // leaving the field empty. Equivalent to both-none
                // for the user; don't emit a drift card.
                None
            }
        }

        // Approved something, candidate none — the fetcher degraded
        // for the current install. Downgrade to no-signal per the
        // §7.2 "(Some, None) → OK" rule: we can't claim drift on a
        // transient fetch failure.
        (Some(_), None) => None,

        (Some(a), Some(c)) => match (a.present, c.present) {
            (false, false) => None, // neither version had provenance
            (false, true) => Some(ProvenanceDriftKind::Gained),
            (true, false) => Some(ProvenanceDriftKind::Dropped),
            (true, true) => {
                if provenance_identity_equal(a, c) {
                    None
                } else {
                    Some(ProvenanceDriftKind::IdentityChanged)
                }
            }
        },
    }
}

/// Classify the behavioral-tag shift given the `(approved,
/// candidate)` tag name sets.
///
/// Returns `None` when:
/// - Either side is `None` (missing signal — can't claim drift).
/// - Both sides are `Some` and the sets are equal (hash comparison
///   does the fast-path check upstream; this is the structural
///   fallback).
///
/// Returns `Some(TagShift)` with sorted `gained` / `lost` when at
/// least one tag differs. The input is assumed to already be sorted
/// (per `BehavioralTags::active_tag_names()`), which makes the
/// set-difference pass O(n+m) via a merge rather than requiring a
/// HashSet per call.
fn classify_tags(approved: Option<&[String]>, candidate: Option<&[String]>) -> Option<TagShift> {
    let (approved, candidate) = match (approved, candidate) {
        (Some(a), Some(c)) => (a, c),
        _ => return None,
    };

    // Both inputs are sorted-ascending (active_tag_names() guarantee);
    // walk both cursors and fall out on side-only entries.
    let mut gained: Vec<String> = Vec::new();
    let mut lost: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < approved.len() && j < candidate.len() {
        match approved[i].cmp(&candidate[j]) {
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => {
                // Present on approved-side only → lost.
                lost.push(approved[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                // Present on candidate-side only → gained.
                gained.push(candidate[j].clone());
                j += 1;
            }
        }
    }
    // Drain whichever side has leftovers.
    while i < approved.len() {
        lost.push(approved[i].clone());
        i += 1;
    }
    while j < candidate.len() {
        gained.push(candidate[j].clone());
        j += 1;
    }

    if gained.is_empty() && lost.is_empty() {
        None
    } else {
        Some(TagShift { gained, lost })
    }
}

/// Classify the script-hash dimension.
///
/// Returns `true` iff both sides have a `Some(hash)` AND the hashes
/// differ. Missing-on-either-side is `false` (no signal).
fn classify_script_hash(approved: Option<&str>, candidate: Option<&str>) -> bool {
    match (approved, candidate) {
        (Some(a), Some(c)) => a != c,
        _ => false,
    }
}

/// Compute the version diff between a prior-approved binding and a
/// candidate `BlockedPackage`.
///
/// Pure: no I/O, no allocations beyond the returned structure. The
/// renderer (C2/C3) and the JSON emitter (C4) consume the returned
/// [`VersionDiff`] value.
///
/// Returns a [`VersionDiff`] with [`VersionDiffReason::NoChange`] when
/// every dimension is equal or contributes no signal. Callers can
/// branch on [`VersionDiff::is_drift`] to decide whether to render.
pub fn compute_version_diff(
    prior_version: &str,
    binding: &TrustedDependencyBinding,
    candidate: &BlockedPackage,
) -> VersionDiff {
    // Fast-path: if the binding's captured script_hash equals the
    // candidate's AND the behavioral_tags_hashes equal (or both are
    // None) AND the provenance tuples equal (or no signal), we can
    // short-circuit to NoChange without any allocation.
    //
    // Done via the per-dimension classifiers below, which each return
    // a "no signal / no change" sentinel; we aggregate after so the
    // diff-bearing cases produce the structured output.
    let script_drift = classify_script_hash(
        binding.script_hash.as_deref(),
        candidate.script_hash.as_deref(),
    );

    // Behavioral tags: compare hashes first for fast equality when
    // both sides have the hash. If either hash is None we fall back
    // to the name-set comparison directly — the hash is a
    // fingerprint optimization, not a semantic requirement.
    //
    // When hashes are both Some and equal, the sets are also equal
    // (the hash was computed FROM the names via `hash_behavioral_tag_set`
    // — same input, same output), so we can skip the merge-walk.
    let tags_equal_by_hash = matches!(
        (
            binding.behavioral_tags_hash.as_deref(),
            candidate.behavioral_tags_hash.as_deref(),
        ),
        (Some(a), Some(c)) if a == c
    );
    let tags_shift = if tags_equal_by_hash {
        None
    } else {
        classify_tags(
            binding.behavioral_tags.as_deref(),
            candidate.behavioral_tags.as_deref(),
        )
    };

    let provenance_drift = classify_provenance(
        binding.provenance_at_approval.as_ref(),
        candidate.provenance_at_capture.as_ref(),
    );

    let reason = match (script_drift, &tags_shift, &provenance_drift) {
        // No dimension drifted.
        (false, None, None) => VersionDiffReason::NoChange,
        // Single-dimension drifts.
        (true, None, None) => VersionDiffReason::ScriptHashDrift,
        (false, Some(shift), None) => VersionDiffReason::BehavioralTagShift {
            gained: shift.gained.clone(),
            lost: shift.lost.clone(),
        },
        (false, None, Some(kind)) => VersionDiffReason::ProvenanceDrift { kind: kind.clone() },
        // Multi-dimension drift — record each present dimension.
        _ => VersionDiffReason::MultiFieldDrift {
            script_hash: script_drift,
            tags: tags_shift,
            provenance: provenance_drift,
        },
    };

    VersionDiff {
        prior_version: prior_version.to_string(),
        candidate_version: candidate.version.clone(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_state::BlockedPackage;
    use lpm_workspace::{ProvenanceSnapshot, TrustedDependencyBinding};

    // ─── Fixtures ─────────────────────────────────────────────────

    fn candidate(name: &str, version: &str) -> BlockedPackage {
        BlockedPackage {
            name: name.into(),
            version: version.into(),
            integrity: Some(format!("sha512-{name}-{version}")),
            script_hash: Some(format!("sha256-{name}-{version}")),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    fn snapshot(publisher: &str, workflow_path: &str) -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some(publisher.into()),
            workflow_path: Some(workflow_path.into()),
            workflow_ref: Some("refs/tags/vX.Y.Z".into()),
            attestation_cert_sha256: Some("sha256-leaf".into()),
        }
    }

    fn snapshot_absent() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: false,
            ..Default::default()
        }
    }

    // ─── compute_version_diff — primary variants ──────────────────

    #[test]
    fn no_change_when_all_dimensions_equal() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-tags-same".into()),
            behavioral_tags: Some(vec!["network".into()]),
            provenance_at_approval: Some(snapshot(
                "github:axios/axios",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("axios", "1.14.1");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-tags-same".into());
        cand.behavioral_tags = Some(vec!["network".into()]);
        // Candidate has a DIFFERENT workflow_ref and cert — those are
        // excluded from identity equality, so this is still NoChange.
        let mut cand_prov = snapshot("github:axios/axios", ".github/workflows/publish.yml");
        cand_prov.workflow_ref = Some("refs/tags/v1.14.1".into());
        cand_prov.attestation_cert_sha256 = Some("sha256-leaf-bbb".into());
        cand.provenance_at_capture = Some(cand_prov);

        let diff = compute_version_diff("1.14.0", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::NoChange);
        assert!(!diff.is_drift());
        assert_eq!(diff.prior_version, "1.14.0");
        assert_eq!(diff.candidate_version, "1.14.1");
    }

    #[test]
    fn script_hash_drift_alone() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            ..Default::default()
        };
        let mut cand = candidate("esbuild", "0.25.2");
        cand.script_hash = Some("sha256-new".into());

        let diff = compute_version_diff("0.25.1", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::ScriptHashDrift);
        assert!(diff.is_drift());
    }

    #[test]
    fn behavioral_tag_shift_gained_tags_surface() {
        // Ship criterion 2: "Updating a package whose behavioral tags
        // gained `network` or `eval` surfaces the delta."
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        };
        let mut cand = candidate("suspicious", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "eval".into(), "network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::BehavioralTagShift { gained, lost } => {
                assert_eq!(gained, vec!["eval".to_string(), "network".to_string()]);
                assert!(lost.is_empty());
            }
            other => panic!("expected BehavioralTagShift, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_tag_shift_lost_tags_surface() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec![
                "crypto".into(),
                "eval".into(),
                "network".into(),
                "shell".into(),
            ]),
            ..Default::default()
        };
        let mut cand = candidate("legit", "3.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "network".into()]);

        let diff = compute_version_diff("2.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::BehavioralTagShift { gained, lost } => {
                assert!(gained.is_empty());
                assert_eq!(lost, vec!["eval".to_string(), "shell".to_string()]);
            }
            other => panic!("expected BehavioralTagShift, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_tag_shift_gained_and_lost_together() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into(), "filesystem".into()]),
            ..Default::default()
        };
        let mut cand = candidate("mixed", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "network".into(), "shell".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::BehavioralTagShift { gained, lost } => {
                assert_eq!(gained, vec!["network".to_string(), "shell".to_string()]);
                assert_eq!(lost, vec!["filesystem".to_string()]);
            }
            other => panic!("expected BehavioralTagShift, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_tags_equal_by_hash_skips_name_set_comparison() {
        // When hashes are both Some and equal, trust the hash — don't
        // re-walk the name sets. Defensive: if the names somehow
        // disagreed with the hash (impossible if the capture used
        // hash_behavioral_tag_set honestly, but we don't want to
        // surface phantom drifts on hash collision-free inputs that
        // genuinely match).
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-tags".into()),
            // Deliberately different from candidate — but the hash
            // says they're equal.
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        };
        let mut cand = candidate("same", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-tags".into());
        cand.behavioral_tags = Some(vec!["network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::NoChange,
            "hash equality must short-circuit to NoChange even if the name sets look different"
        );
    }

    #[test]
    fn provenance_identity_changed() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot(
                "github:axios/axios",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("axios", "1.15.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = Some(snapshot(
            "github:evil/axios-fork",
            ".github/workflows/publish.yml",
        ));

        let diff = compute_version_diff("1.14.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::IdentityChanged
            }
        );
    }

    #[test]
    fn provenance_dropped_axios_pattern() {
        // The axios 1.14.1 pattern: prior release had provenance, new
        // release dropped it.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot(
                "github:axios/axios",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("axios", "1.14.1");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = Some(snapshot_absent());

        let diff = compute_version_diff("1.14.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::Dropped
            }
        );
    }

    #[test]
    fn provenance_gained_is_informational() {
        // Prior version had no attestation; candidate has one. The
        // drift gate treats this as NoDrift (strictly better signal),
        // but the diff UI surfaces it as `Gained` so the user knows
        // the security posture improved.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot_absent()),
            ..Default::default()
        };
        let mut cand = candidate("rising", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = Some(snapshot(
            "github:rising/package",
            ".github/workflows/publish.yml",
        ));

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::Gained
            }
        );
    }

    // ─── Multi-field drift ────────────────────────────────────────

    #[test]
    fn multi_field_drift_script_and_tags() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        };
        let mut cand = candidate("compromise", "2.0.0");
        cand.script_hash = Some("sha256-new".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::MultiFieldDrift {
                script_hash,
                tags,
                provenance,
            } => {
                assert!(script_hash);
                assert_eq!(
                    tags,
                    Some(TagShift {
                        gained: vec!["network".into()],
                        lost: vec![],
                    })
                );
                assert_eq!(provenance, None);
            }
            other => panic!("expected MultiFieldDrift, got {other:?}"),
        }
    }

    #[test]
    fn multi_field_drift_all_three_dimensions() {
        // Supply-chain worst-case: script body AND tags AND
        // provenance all rotate.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            behavioral_tags_hash: Some("sha256-tags-old".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            provenance_at_approval: Some(snapshot(
                "github:legit/pkg",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("compromise", "2.0.0");
        cand.script_hash = Some("sha256-new".into());
        cand.behavioral_tags_hash = Some("sha256-tags-new".into());
        cand.behavioral_tags = Some(vec!["eval".into(), "network".into(), "shell".into()]);
        cand.provenance_at_capture = Some(snapshot_absent());

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::MultiFieldDrift {
                script_hash,
                tags,
                provenance,
            } => {
                assert!(script_hash);
                assert_eq!(
                    tags,
                    Some(TagShift {
                        gained: vec!["eval".into(), "network".into(), "shell".into()],
                        lost: vec!["crypto".into()],
                    })
                );
                assert_eq!(provenance, Some(ProvenanceDriftKind::Dropped));
            }
            other => panic!("expected MultiFieldDrift, got {other:?}"),
        }
    }

    // ─── Missing-signal edge cases ───────────────────────────────

    #[test]
    fn missing_script_hash_on_either_side_is_no_signal() {
        // Binding lacks script_hash (legacy / pre-Phase-4 upgrade).
        let binding = TrustedDependencyBinding {
            script_hash: None,
            ..Default::default()
        };
        let mut cand = candidate("legacy", "2.0.0");
        cand.script_hash = Some("sha256-new".into());

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::NoChange,
            "None binding.script_hash → no signal on that dimension"
        );

        // Now the candidate lacks it.
        let binding2 = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            ..Default::default()
        };
        let mut cand2 = candidate("other", "2.0.0");
        cand2.script_hash = None;

        let diff2 = compute_version_diff("1.0.0", &binding2, &cand2);
        assert_eq!(diff2.reason, VersionDiffReason::NoChange);
    }

    #[test]
    fn missing_behavioral_tags_on_either_side_is_no_signal() {
        // Binding lacks tags entirely.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: None,
            behavioral_tags: None,
            ..Default::default()
        };
        let mut cand = candidate("no-tags-before", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::NoChange,
            "missing binding.behavioral_tags → can't claim drift on that dimension"
        );
    }

    #[test]
    fn both_sides_have_no_provenance_is_no_change() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: None,
            ..Default::default()
        };
        let mut cand = candidate("no-prov", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = None;

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::NoChange);
    }

    #[test]
    fn prior_had_snapshot_absent_candidate_missing_entirely_is_no_change() {
        // Prior captured `present: false` (we fetched, registry said
        // no attestation). Candidate is None (fetcher degraded). No
        // drift signal — the `(Some, None)` case is documented as
        // pass-through.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot_absent()),
            ..Default::default()
        };
        let mut cand = candidate("degraded", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = None;

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::NoChange);
    }

    // ─── latest_binding_for_name (workspace-side helper, exercised
    //     here via the full P7 integration surface) ────────────────

    #[test]
    fn latest_binding_selects_strictly_less_than_candidate() {
        use lpm_workspace::TrustedDependencies;
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-v1140".into()),
                ..Default::default()
            },
        );
        map.insert(
            "axios@1.13.5".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-v1135".into()),
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        // Candidate 1.14.1 → lex-max strictly-less-than is 1.14.0.
        let (v, b) = td.latest_binding_for_name("axios", "1.14.1").unwrap();
        assert_eq!(v, "1.14.0");
        assert_eq!(b.script_hash.as_deref(), Some("sha256-v1140"));

        // Candidate 1.14.0 → strictly-less-than → 1.13.5.
        let (v2, _) = td.latest_binding_for_name("axios", "1.14.0").unwrap();
        assert_eq!(v2, "1.13.5");

        // Candidate 1.13.5 → no prior (can't pick itself).
        assert!(td.latest_binding_for_name("axios", "1.13.5").is_none());

        // Candidate 1.12.0 → nothing is strictly less.
        assert!(td.latest_binding_for_name("axios", "1.12.0").is_none());

        // Unknown package name → None.
        assert!(td.latest_binding_for_name("express", "5.0.0").is_none());
    }

    #[test]
    fn latest_binding_skips_at_star_preserve_key() {
        use lpm_workspace::TrustedDependencies;
        use std::collections::HashMap;

        // A legacy upgrade preserve key `axios@*` must NOT be picked
        // as a prior version — `*` lex-sorts higher than any concrete
        // digit, so a naive max would return it.
        let mut map = HashMap::new();
        map.insert("axios@*".into(), TrustedDependencyBinding::default());
        map.insert(
            "axios@1.13.0".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-v1130".into()),
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        let (v, _) = td.latest_binding_for_name("axios", "1.14.0").unwrap();
        assert_eq!(v, "1.13.0", "`@*` preserve keys must be excluded");
    }

    #[test]
    fn latest_binding_handles_scoped_package_names() {
        use lpm_workspace::TrustedDependencies;
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(
            "@scope/pkg@1.0.0".into(),
            TrustedDependencyBinding::default(),
        );
        let td = TrustedDependencies::Rich(map);

        let (v, _) = td.latest_binding_for_name("@scope/pkg", "1.1.0").unwrap();
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn latest_binding_returns_none_for_legacy_variant() {
        use lpm_workspace::TrustedDependencies;

        let td = TrustedDependencies::Legacy(vec!["axios".into()]);
        assert!(td.latest_binding_for_name("axios", "1.0.0").is_none());
    }
}
