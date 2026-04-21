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
    /// No drift detected. Either the identity tuple matches exactly,
    /// or we have insufficient signal on one or both sides to claim
    /// drift. The install proceeds (subject to other gates).
    NoDrift,
    /// The approved version had a Sigstore attestation; the candidate
    /// version does not. This is the axios 1.14.1 pattern: every
    /// legitimate release carried GitHub OIDC provenance, the
    /// malicious release dropped it. Blocks install without
    /// `--ignore-provenance-drift`.
    ProvenanceDropped,
    /// Both versions carry attestations, but the identity tuple
    /// (publisher + workflow_path) differs. A maintainer could
    /// legitimately move a repo between orgs or change the workflow
    /// file, but the user should acknowledge the change before
    /// scripts run. Blocks install without
    /// `--ignore-provenance-drift`.
    IdentityChanged,
}

/// Compare the approved-side and fresh-side snapshots using only the
/// **stable identity fields**: `present`, `publisher`, and
/// `workflow_path`.
///
/// Deliberately excluded from the identity tuple:
/// - `workflow_ref` (e.g. `refs/tags/v1.14.0`) — changes every
///   release by design; comparing it would falsely flag every patch
///   bump as "identity changed" (this was the reviewer's critical
///   Chunk 3 finding before the workflow field split).
/// - `attestation_cert_sha256` — Fulcio issues a fresh leaf cert per
///   signing invocation, so the cert SHA rotates per release even
///   when the GitHub Actions identity is unchanged. Retained in the
///   snapshot for audit / forensics, not for drift gating.
///
/// Using `==` on the full struct (which is what Chunk 3 originally
/// did) would have made `NoDrift` unreachable for any two distinct
/// releases from the same repo — the regression guard
/// `no_drift_when_only_workflow_ref_differs_between_releases` below
/// exercises exactly this scenario and must stay green.
fn identity_equal(a: &ProvenanceSnapshot, n: &ProvenanceSnapshot) -> bool {
    a.present == n.present && a.publisher == n.publisher && a.workflow_path == n.workflow_path
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

        // Identity tuple matches. This covers the common case where a
        // trusted publisher ships a new patch from the same repo +
        // workflow file. The ref and cert SHA almost certainly differ
        // across releases (the Fulcio leaf cert rotates per signing),
        // but those fields are intentionally excluded from the
        // identity tuple per `identity_equal`'s doc comment.
        (Some(a), Some(n)) if identity_equal(a, n) => DriftVerdict::NoDrift,

        // Approved side had provenance; current side confirms no
        // provenance. The axios signal. Block.
        (Some(a), Some(n)) if a.present && !n.present => DriftVerdict::ProvenanceDropped,

        // Approved side had no provenance; current side has it. The
        // package "gained" provenance — a strictly-better security
        // signal than the approved reference. Let it through; the
        // user can re-approve to capture the new snapshot and tighten
        // subsequent drift checks.
        (Some(a), Some(n)) if !a.present && n.present => DriftVerdict::NoDrift,

        // Both present with identity tuple disagreement on publisher
        // and/or workflow_path: identity changed. Block.
        (Some(_), Some(_)) => DriftVerdict::IdentityChanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_full(
        publisher: &str,
        workflow_path: &str,
        workflow_ref: &str,
        cert: &str,
    ) -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some(publisher.into()),
            workflow_path: Some(workflow_path.into()),
            workflow_ref: Some(workflow_ref.into()),
            attestation_cert_sha256: Some(cert.into()),
        }
    }

    fn snap_absent() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: false,
            ..Default::default()
        }
    }

    // ── §7.2 five-branch match table ──────────────────────────────

    // Canonical stable-fields identity used as the base for drift
    // tests. `axios_v114_0` vs `axios_v114_1` cover the "same repo,
    // same workflow file, different release" case — the scenario the
    // reviewer flagged as catastrophically misclassified by the
    // original `==`-based comparator. All identity-equal pairs must
    // resolve to `NoDrift`.
    const PUB_AXIOS: &str = "github:axios/axios";
    const WORKFLOW_PATH: &str = ".github/workflows/publish.yml";

    fn axios_v114_0() -> ProvenanceSnapshot {
        snap_full(
            PUB_AXIOS,
            WORKFLOW_PATH,
            "refs/tags/v1.14.0",
            "sha256-leaf-aaa",
        )
    }

    fn axios_v114_1() -> ProvenanceSnapshot {
        snap_full(
            PUB_AXIOS,
            WORKFLOW_PATH,
            "refs/tags/v1.14.1",
            "sha256-leaf-bbb",
        )
    }

    #[test]
    fn no_drift_when_approved_and_now_match_exactly() {
        let a = axios_v114_0();
        let n = a.clone();
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::NoDrift
        );
    }

    /// **Reviewer finding — Finding 1 primary regression guard.** A
    /// legitimate v1.14.0 → v1.14.1 release from the same repo + same
    /// workflow file necessarily carries a different `workflow_ref`
    /// (release tag) and a different `attestation_cert_sha256`
    /// (Fulcio's ephemeral leaf rotates per signing). Pre-fix, the
    /// comparator used full-struct `==` and classified every such
    /// release as `IdentityChanged` — which would block every
    /// legitimate axios release forever. Post-fix, identity
    /// equality is scoped to `publisher + workflow_path`, so this
    /// pair MUST resolve to `NoDrift`.
    #[test]
    fn no_drift_when_only_workflow_ref_differs_between_releases() {
        let v0 = axios_v114_0();
        let v1 = axios_v114_1();
        assert_ne!(
            v0.workflow_ref, v1.workflow_ref,
            "fixture precondition: refs differ",
        );
        assert_ne!(
            v0.attestation_cert_sha256, v1.attestation_cert_sha256,
            "fixture precondition: cert SHA also differs per release",
        );
        assert_eq!(
            check_provenance_drift(Some(&v0), Some(&v1)),
            DriftVerdict::NoDrift,
            "same publisher + workflow_path across releases is NOT drift — \
             cross-release ref + cert rotation is the expected steady state",
        );
    }

    /// **Reviewer finding — Finding 1 secondary regression guard.**
    /// Even with identical publisher + workflow_path + workflow_ref,
    /// two signings of the same workflow necessarily produce
    /// different Fulcio leaf certs (the leaf is ephemeral, bound to
    /// the signing invocation). Pre-fix: `IdentityChanged`.
    /// Post-fix: `NoDrift`.
    #[test]
    fn no_drift_when_only_cert_sha_differs_across_rotations() {
        let a = axios_v114_0();
        let n = ProvenanceSnapshot {
            attestation_cert_sha256: Some("sha256-different-leaf".into()),
            ..a.clone()
        };
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::NoDrift,
            "cert SHA rotates per Fulcio signing — it must not trigger drift alone",
        );
    }

    #[test]
    fn identity_changed_when_publisher_differs() {
        let a = axios_v114_0();
        let n = snap_full(
            "github:attacker-fork/axios",
            WORKFLOW_PATH,
            "refs/tags/v1.14.1",
            "sha256-leaf-bbb",
        );
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::IdentityChanged
        );
    }

    #[test]
    fn identity_changed_when_workflow_path_differs() {
        // Same repo + release tag, but a DIFFERENT workflow file —
        // e.g. an attacker-triggered PR workflow masquerading as the
        // main publish workflow. `workflow_path` IS part of the
        // identity tuple because it names the stable build surface.
        let a = axios_v114_0();
        let n = snap_full(
            PUB_AXIOS,
            ".github/workflows/pr-workflow.yml",
            "refs/tags/v1.14.0",
            "sha256-leaf-bbb",
        );
        assert_eq!(
            check_provenance_drift(Some(&a), Some(&n)),
            DriftVerdict::IdentityChanged
        );
    }

    #[test]
    fn provenance_dropped_when_approved_present_and_now_absent() {
        // The primary axios-1.14.1 signal. Block.
        let a = axios_v114_0();
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
        let n = axios_v114_0();
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
        let n = axios_v114_0();
        assert_eq!(
            check_provenance_drift(None, Some(&n)),
            DriftVerdict::NoDrift
        );
    }

    #[test]
    fn no_drift_when_now_side_is_none() {
        // Fetcher returned None (degraded). Per §11 P4, don't block
        // the install over transient network conditions.
        let a = axios_v114_0();
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
        let approved = axios_v114_0();

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
