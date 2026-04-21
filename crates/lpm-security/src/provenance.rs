//! Phase 46 P4 Chunk 3 — provenance-drift comparator.
//!
//! Pure comparison logic consumed by the install-time drift gate in
//! `lpm-cli/src/commands/install.rs`. Given an approved
//! [`ProvenanceSnapshot`] (captured into a
//! [`TrustedDependencyBinding.provenance_at_approval`] at approval
//! time) and a freshly-fetched snapshot for the candidate version,
//! decide whether the identity has drifted enough to block the
//! install.
//!
//! Maps to §7.2 of the Phase 46 plan:
//!
//! ```text
//! (now, approved)
//! (Some(n), Some(a)) if n == a   → pass
//! (Some(_), Some(_))             → drift!("identity changed")
//! (None, Some(_))                → drift!("provenance dropped")
//! (Some(_), None)                → OK — present now, wasn't at approval
//! (None, None)                   → never had it — layers 1/2/4 decide
//! ```
//!
//! **Where `None` comes from** — outer `Option<&ProvenanceSnapshot>`
//! is distinct from the snapshot's inner `present: bool`:
//! - Outer `None` (approved side): no approval record has a captured
//!   snapshot — legacy binding, or approval pre-dated P4.
//! - Outer `None` (now side): the fetcher couldn't produce a
//!   definitive answer (network error, malformed bundle). Per §11 P4,
//!   fetch failures degrade to pass, NOT drift.
//! - Inner `present: false`: the registry **confirms** it has no
//!   attestation for this version — that's the axios signal when the
//!   approved side was `present: true`.
//!
//! The comparator is intentionally pure (no I/O, no config) so Chunk
//! 5's E2E tests can drive it through real fetches while
//! `provenance::tests` here drive it through synthetic snapshots.

use lpm_workspace::ProvenanceSnapshot;

/// Result of a drift check between an approved-side snapshot and a
/// freshly-fetched one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftVerdict {
    /// No drift detected. Either the snapshots match exactly, or we
    /// have insufficient signal on one or both sides to claim drift.
    /// The install proceeds (subject to other gates).
    NoDrift,
    /// The approved version had a Sigstore attestation; the candidate
    /// version does not. This is the axios 1.14.1 pattern: every
    /// legitimate release carried GitHub OIDC provenance, the
    /// malicious release dropped it. Blocks install without
    /// `--ignore-provenance-drift`.
    ProvenanceDropped,
    /// Both versions carry attestations, but the identity tuple
    /// (publisher / workflow / cert SHA) differs. A maintainer could
    /// legitimately move a repo between orgs, but the user should
    /// acknowledge the change before scripts run. Blocks install
    /// without `--ignore-provenance-drift`.
    IdentityChanged,
}

/// Compare the approved-side and fresh-side provenance snapshots per
/// the §7.2 drift rule.
///
/// Returns [`DriftVerdict::NoDrift`] whenever the comparison cannot
/// claim drift with confidence — this is the plan's "pass, don't
/// drift" contract for degraded-fetch and missing-approval cases.
/// Callers should still surface drift visually (e.g., the UX in §7.3)
/// only when the verdict is not `NoDrift`.
pub fn check_provenance_drift(
    approved: Option<&ProvenanceSnapshot>,
    now: Option<&ProvenanceSnapshot>,
) -> DriftVerdict {
    match (approved, now) {
        // No approval reference: can't detect drift. Either a legacy
        // `trustedDependencies` entry with no P4 state, or the binding
        // was written before P4 captured provenance. Layers 1/2/4
        // (static gate, cooldown, etc.) decide.
        (None, _) => DriftVerdict::NoDrift,

        // Degraded fetch: network error, malformed bundle, cache
        // unusable — we don't have a reliable "now" signal. Per the
        // plan's offline-mode contract, degrade to pass rather than
        // block on transient conditions.
        (Some(_), None) => DriftVerdict::NoDrift,

        // Exact tuple match: no drift. This covers the common case
        // where a trusted publisher ships a new patch with the same
        // workflow + cert chain (or at least the same cert SHA — the
        // ephemeral Fulcio leaf differs per run, but the identity
        // triple `present + publisher + workflow` does not).
        (Some(a), Some(n)) if a == n => DriftVerdict::NoDrift,

        // Approved side had provenance; current side confirms no
        // provenance. The axios signal. Block.
        (Some(a), Some(n)) if a.present && !n.present => DriftVerdict::ProvenanceDropped,

        // Approved side had no provenance; current side has it. The
        // package "gained" provenance — a strictly-better security
        // signal than the approved reference. Let it through; the
        // user can re-approve to capture the new snapshot and tighten
        // subsequent drift checks.
        (Some(a), Some(n)) if !a.present && n.present => DriftVerdict::NoDrift,

        // Both present, tuple differs on at least one field: identity
        // changed. Block.
        (Some(_), Some(_)) => DriftVerdict::IdentityChanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_full(publisher: &str, workflow: &str, cert: &str) -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some(publisher.into()),
            workflow: Some(workflow.into()),
            attestation_cert_sha256: Some(cert.into()),
        }
    }

    fn snap_absent() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: false,
            publisher: None,
            workflow: None,
            attestation_cert_sha256: None,
        }
    }

    // ── §7.2 five-branch match table ──────────────────────────────

    #[test]
    fn no_drift_when_approved_and_now_match_exactly() {
        let a = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        let n = a.clone();
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::NoDrift
        );
    }

    #[test]
    fn identity_changed_when_both_present_but_publisher_differs() {
        let a = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        let n = snap_full(
            "github:attacker-fork/axios",
            "publish.yml@v1.14.1",
            "sha256-bbb",
        );
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::IdentityChanged
        );
    }

    #[test]
    fn identity_changed_when_only_workflow_differs() {
        // Same repo, but an attacker-triggered PR workflow
        // masquerading as the main publish workflow.
        let a = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        let n = snap_full(
            "github:axios/axios",
            "pr-workflow.yml@v1.14.1",
            "sha256-bbb",
        );
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::IdentityChanged
        );
    }

    #[test]
    fn identity_changed_when_only_cert_sha_differs() {
        // Same publisher + workflow string, but the cert SHA is
        // different — Fulcio's ephemeral leaf doesn't actually match
        // across runs in practice, so this case is a bit artificial
        // for GitHub Actions today. Tests the comparator's strict
        // tuple equality regardless.
        let a = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        let n = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-bbb");
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::IdentityChanged
        );
    }

    #[test]
    fn provenance_dropped_when_approved_present_and_now_absent() {
        // The primary axios-1.14.1 signal. Block.
        let a = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        let n = snap_absent();
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::ProvenanceDropped
        );
    }

    #[test]
    fn no_drift_when_approved_absent_and_now_present() {
        // Package gained provenance. Strictly-better signal than the
        // approved reference — allow through. User can re-approve
        // to tighten the subsequent gate.
        let a = snap_absent();
        let n = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::NoDrift
        );
    }

    #[test]
    fn no_drift_when_both_absent() {
        let a = snap_absent();
        let n = snap_absent();
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::NoDrift
        );
    }

    // ── Outer-Option branches (degraded / legacy) ─────────────────

    #[test]
    fn no_drift_when_approved_side_is_none() {
        // Legacy binding or pre-P4 approval — no reference to drift
        // from. Layers 1/2/4 decide.
        let n = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        assert_eq!(
            check_provenance_drift(None, Some(&n)),
            DriftVerdict::NoDrift
        );
    }

    #[test]
    fn no_drift_when_now_side_is_none() {
        // Fetcher returned None (degraded). Per §11 P4, don't block
        // the install over transient network conditions.
        let a = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");
        assert_eq!(
            check_provenance_drift(Some(&a), None),
            DriftVerdict::NoDrift
        );
    }

    #[test]
    fn no_drift_when_both_sides_are_none() {
        assert_eq!(check_provenance_drift(None, None), DriftVerdict::NoDrift);
    }

    // ── Degraded + drift signals don't leak into each other ──────

    /// Regression guard: a degraded-fetch (`now = None`) must never
    /// be mistaken for "provenance dropped" (`now = Some(present:
    /// false)`). The two states look similar but have opposite
    /// verdicts — a transient fetch failure should never trigger a
    /// block, and a registry-confirmed absence should always trigger
    /// one (when the approved side had provenance).
    #[test]
    fn degraded_fetch_distinct_from_confirmed_absent() {
        let approved = snap_full("github:axios/axios", "publish.yml@v1.14.0", "sha256-aaa");

        // Degraded → NoDrift (pass)
        assert_eq!(
            check_provenance_drift(Some(&approved), None),
            DriftVerdict::NoDrift,
        );
        // Confirmed absent → ProvenanceDropped (block)
        let absent = snap_absent();
        assert_eq!(
            check_provenance_drift(Some(&approved), Some(&absent)),
            DriftVerdict::ProvenanceDropped,
        );
    }
}
